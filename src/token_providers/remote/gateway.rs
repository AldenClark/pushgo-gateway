use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use reqwest::{
    Client, StatusCode, Url,
    header::{HeaderValue, RETRY_AFTER},
    redirect,
};
use serde::Deserialize;
use tokio::sync::Mutex;

use pushgo_gateway::{Error, providers::TokenInfo};

const TOKEN_ENDPOINT_PATH: &str = "/provider/token";
const TOKEN_SANDBOX_ENDPOINT_PATH: &str = "/provider/token/sandbox";
const TOKEN_PRODUCTION_ENDPOINT_PATH: &str = "/provider/token/production";
const TOKEN_REFRESH_BUFFER: Duration = Duration::from_secs(60);
const TOKEN_MIN_REUSABLE_TTL: Duration = Duration::from_secs(1);
const TOKEN_MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const TOKEN_SERVICE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_SERVICE_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN_SERVICE_MAX_ATTEMPTS: usize = 3;
const TOKEN_SERVICE_RETRY_DELAYS: [Duration; TOKEN_SERVICE_MAX_ATTEMPTS - 1] =
    [Duration::from_millis(100), Duration::from_millis(200)];
const TOKEN_SERVICE_MAX_REDIRECTS: usize = 3;
const TOKEN_SERVICE_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const TOKEN_SERVICE_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const TOKEN_SERVICE_MAX_RETRY_AFTER: Duration = Duration::from_secs(5);

pub(crate) fn build_token_service_http_client() -> Result<Client, Error> {
    Client::builder()
        .user_agent(concat!("pushgo-gateway/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(TOKEN_SERVICE_CONNECT_TIMEOUT)
        .timeout(TOKEN_SERVICE_REQUEST_TIMEOUT)
        .redirect(token_service_redirect_policy())
        .build()
        .map_err(|_| Error::Internal("failed to initialize token service client".to_string()))
}

fn token_service_redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(|attempt| {
        let Some(original) = attempt.previous().first() else {
            return attempt.error("token service redirect has no origin");
        };
        if attempt.previous().len() > TOKEN_SERVICE_MAX_REDIRECTS {
            return attempt.error("token service redirect limit exceeded");
        }
        if !same_origin(original, attempt.url()) {
            return attempt.error("cross-origin token service redirect denied");
        }
        attempt.follow()
    })
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left
            .host_str()
            .zip(right.host_str())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && left.port_or_known_default() == right.port_or_known_default()
}

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
    generation: u64,
}

pub(crate) struct GatewayTokenCache {
    client: Client,
    provider: GatewayProvider,
    base_url: Arc<str>,
    state: Arc<ArcSwap<GatewayTokenState>>,
    refresh: Mutex<RefreshCoordinator>,
}

#[derive(Default)]
struct RefreshCoordinator {
    terminal_auth_status: Option<u16>,
    failure_backoff: Option<FailureBackoff>,
}

struct FailureBackoff {
    until: Instant,
    status: u16,
}

#[derive(Clone, Copy)]
enum RefreshIntent {
    Opportunistic,
    Explicit,
}

#[derive(Clone, Copy)]
enum TokenRequirement {
    TokenOnly,
    TokenWithProject,
}

struct FetchFailure {
    error: Error,
    retryable: bool,
    retry_after: Option<Duration>,
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
            generation: 0,
        };
        Self {
            client,
            provider,
            base_url: Arc::from(base_url.into_boxed_str()),
            state: Arc::new(ArcSwap::from_pointee(initial)),
            refresh: Mutex::new(RefreshCoordinator::default()),
        }
    }

    pub(crate) async fn token_info(&self) -> Result<TokenInfo, Error> {
        if let Some(info) = self.cached_token_info(TOKEN_REFRESH_BUFFER) {
            return Ok(info);
        }

        match self.refresh_token(RefreshIntent::Opportunistic).await {
            Ok(info) => Ok(info),
            Err(err) => self.cached_token_info(Duration::ZERO).ok_or(err),
        }
    }

    pub(crate) async fn token_info_with_project(&self) -> Result<(TokenInfo, Arc<str>), Error> {
        if let Some(info) = self.cached_token_info_with_project(TOKEN_REFRESH_BUFFER) {
            return Ok(info);
        }

        match self
            .refresh_token_with_project(RefreshIntent::Opportunistic)
            .await
        {
            Ok((info, project_id)) => Ok((info, project_id)),
            Err(err) => self
                .cached_token_info_with_project(Duration::ZERO)
                .ok_or(err),
        }
    }

    fn cached_token_info(&self, minimum_remaining: Duration) -> Option<TokenInfo> {
        let cached = self.state.load();
        let remaining = cached.expires_at.saturating_duration_since(Instant::now());
        let minimum_remaining = minimum_remaining.max(TOKEN_MIN_REUSABLE_TTL);
        if cached.token.is_empty() || remaining <= minimum_remaining {
            return None;
        }
        Some(TokenInfo {
            token: Arc::clone(&cached.token),
            expires_in: remaining.as_secs(),
        })
    }

    fn cached_token_info_with_project(
        &self,
        minimum_remaining: Duration,
    ) -> Option<(TokenInfo, Arc<str>)> {
        let cached = self.state.load();
        let remaining = cached.expires_at.saturating_duration_since(Instant::now());
        let minimum_remaining = minimum_remaining.max(TOKEN_MIN_REUSABLE_TTL);
        let project_id = cached.project_id.as_ref()?;
        if cached.token.is_empty() || remaining <= minimum_remaining {
            return None;
        }
        Some((
            TokenInfo {
                token: Arc::clone(&cached.token),
                expires_in: remaining.as_secs(),
            },
            Arc::clone(project_id),
        ))
    }

    pub(crate) async fn token_info_fresh(&self) -> Result<TokenInfo, Error> {
        self.refresh_token(RefreshIntent::Explicit).await
    }

    pub(crate) async fn token_info_with_project_fresh(
        &self,
    ) -> Result<(TokenInfo, Arc<str>), Error> {
        self.refresh_token_with_project(RefreshIntent::Explicit)
            .await
    }

    pub(crate) async fn refresh_now(&self) -> Result<Arc<str>, Error> {
        let info = self.refresh_token(RefreshIntent::Explicit).await?;
        Ok(info.token)
    }

    async fn refresh_token(&self, intent: RefreshIntent) -> Result<TokenInfo, Error> {
        let (info, _) = self
            .refresh_token_state(intent, TokenRequirement::TokenOnly)
            .await?;
        Ok(info)
    }

    async fn refresh_token_with_project(
        &self,
        intent: RefreshIntent,
    ) -> Result<(TokenInfo, Arc<str>), Error> {
        let (info, project_id) = self
            .refresh_token_state(intent, TokenRequirement::TokenWithProject)
            .await?;
        let project_id = project_id.ok_or_else(|| {
            Error::Internal(
                "token service response missing project_id for fcm provider".to_string(),
            )
        })?;
        Ok((info, project_id))
    }

    async fn refresh_token_state(
        &self,
        intent: RefreshIntent,
        requirement: TokenRequirement,
    ) -> Result<(TokenInfo, Option<Arc<str>>), Error> {
        let observed_generation = self.state.load().generation;
        let mut coordinator = self.refresh.lock().await;
        if let Some(status) = coordinator.terminal_auth_status {
            return Err(token_service_error_from_status(status));
        }

        let now = Instant::now();
        if let Some(backoff) = coordinator.failure_backoff.as_ref() {
            if backoff.until > now {
                return Err(token_service_error_from_status(backoff.status));
            }
            coordinator.failure_backoff = None;
        }

        let current_generation = self.state.load().generation;
        let minimum_remaining = match intent {
            RefreshIntent::Opportunistic => Some(TOKEN_REFRESH_BUFFER),
            RefreshIntent::Explicit if current_generation != observed_generation => {
                Some(Duration::ZERO)
            }
            RefreshIntent::Explicit => None,
        };
        if let Some(minimum_remaining) = minimum_remaining
            && let Some(cached) = self.cached_token_state(minimum_remaining, requirement)
        {
            return Ok(cached);
        }

        let fetched = self.fetch_token().await;
        let (info, fetched_project_id) = match fetched {
            Ok(result) => result,
            Err(failure) => {
                coordinator.record_failure(&failure.error, failure.retry_after);
                return Err(failure.error);
            }
        };
        let expires_at = match validated_expiry(info.expires_in) {
            Ok(expires_at) => expires_at,
            Err(error) => {
                coordinator.record_failure(&error, None);
                return Err(error);
            }
        };
        let project_id = match requirement {
            TokenRequirement::TokenOnly => fetched_project_id,
            TokenRequirement::TokenWithProject => {
                let project_id = fetched_project_id
                    .or_else(|| self.state.load().project_id.as_ref().map(Arc::clone));
                let Some(project_id) = project_id else {
                    let error = Error::Upstream {
                        provider: "PushGo Token Service",
                        status: 200,
                        message: "token service response missing project_id for fcm provider"
                            .to_string(),
                    };
                    coordinator.record_failure(&error, None);
                    return Err(error);
                };
                Some(project_id)
            }
        };
        let generation = current_generation.saturating_add(1);
        self.state.store(Arc::new(GatewayTokenState {
            token: Arc::clone(&info.token),
            expires_at,
            project_id: project_id.as_ref().map(Arc::clone),
            generation,
        }));
        coordinator.failure_backoff = None;
        Ok((info, project_id))
    }

    fn cached_token_state(
        &self,
        minimum_remaining: Duration,
        requirement: TokenRequirement,
    ) -> Option<(TokenInfo, Option<Arc<str>>)> {
        let cached = self.state.load();
        let remaining = cached.expires_at.saturating_duration_since(Instant::now());
        let minimum_remaining = minimum_remaining.max(TOKEN_MIN_REUSABLE_TTL);
        if cached.token.is_empty() || remaining <= minimum_remaining {
            return None;
        }
        let project_id = cached.project_id.as_ref().map(Arc::clone);
        if matches!(requirement, TokenRequirement::TokenWithProject) && project_id.is_none() {
            return None;
        }
        Some((
            TokenInfo {
                token: Arc::clone(&cached.token),
                expires_in: remaining.as_secs(),
            },
            project_id,
        ))
    }

    async fn fetch_token(&self) -> Result<(TokenInfo, Option<Arc<str>>), FetchFailure> {
        let path = match self.provider {
            GatewayProvider::Apns => {
                if pushgo_gateway::util::is_sandbox_mode() {
                    TOKEN_SANDBOX_ENDPOINT_PATH
                } else {
                    TOKEN_PRODUCTION_ENDPOINT_PATH
                }
            }
            GatewayProvider::Fcm | GatewayProvider::Wns => TOKEN_ENDPOINT_PATH,
        };
        self.fetch_token_from_path(path).await
    }

    async fn fetch_token_from_path(
        &self,
        token_path: &str,
    ) -> Result<(TokenInfo, Option<Arc<str>>), FetchFailure> {
        let url = format!(
            "{}{}?provider={}",
            self.base_url,
            token_path,
            self.provider.as_str()
        );
        let mut retry_delays = TOKEN_SERVICE_RETRY_DELAYS.into_iter();
        loop {
            match self.fetch_token_attempt(url.as_str()).await {
                Ok(token) => return Ok(token),
                Err(current) if current.retryable => {
                    let Some(default_delay) = retry_delays.next() else {
                        return Err(current);
                    };
                    let delay = current
                        .retry_after
                        .unwrap_or_else(|| jittered_backoff(default_delay))
                        .min(TOKEN_SERVICE_MAX_RETRY_AFTER);
                    tokio::time::sleep(delay).await;
                }
                Err(current) => return Err(current),
            }
        }
    }

    async fn fetch_token_attempt(
        &self,
        url: &str,
    ) -> Result<(TokenInfo, Option<Arc<str>>), FetchFailure> {
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| FetchFailure {
                retryable: !error.is_builder()
                    && !error.is_redirect()
                    && (error.is_timeout()
                        || error.is_connect()
                        || error.is_body()
                        || error.is_request()),
                retry_after: None,
                error: Error::Upstream {
                    provider: "PushGo Token Service",
                    status: 0,
                    message: "token service request failed".to_string(),
                },
            })?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(parse_retry_after);
        let header_request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .and_then(safe_observation_value)
            .map(str::to_string);
        if response
            .content_length()
            .is_some_and(|length| length > TOKEN_SERVICE_MAX_RESPONSE_BYTES as u64)
        {
            return Err(FetchFailure::terminal(Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message: "token service response exceeded the size limit".to_string(),
            }));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| FetchFailure {
            retryable: status.is_success() || token_service_status_is_retryable(status),
            retry_after,
            error: Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message: "token service response failed".to_string(),
            },
        })? {
            let next_len = body.len().saturating_add(chunk.len());
            if next_len > TOKEN_SERVICE_MAX_RESPONSE_BYTES {
                return Err(FetchFailure::terminal(Error::Upstream {
                    provider: "PushGo Token Service",
                    status: status.as_u16(),
                    message: "token service response exceeded the size limit".to_string(),
                }));
            }
            body.extend_from_slice(&chunk);
        }

        let error_details = serde_json::from_slice::<GatewayErrorEnvelope>(&body)
            .ok()
            .and_then(|envelope| envelope.error);
        observe_token_service_failure(
            self.provider,
            status,
            error_details.as_ref(),
            header_request_id.as_deref(),
        );

        if !status.is_success() {
            return Err(FetchFailure {
                retryable: token_service_status_is_retryable(status),
                retry_after,
                error: Error::Upstream {
                    provider: "PushGo Token Service",
                    status: status.as_u16(),
                    message: token_service_status_message(status).to_string(),
                },
            });
        }

        let parsed: GatewayResponse<GatewayTokenData> =
            serde_json::from_slice(&body).map_err(|_| {
                FetchFailure::terminal(Error::Upstream {
                    provider: "PushGo Token Service",
                    status: status.as_u16(),
                    message: "token service returned an invalid response".to_string(),
                })
            })?;
        if !parsed.success {
            return Err(FetchFailure::terminal(Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message: "token service rejected the request".to_string(),
            }));
        }
        let data = parsed.data.ok_or_else(|| {
            FetchFailure::terminal(Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message: "token service response missing data".to_string(),
            })
        })?;
        let token = data.token.ok_or_else(|| {
            FetchFailure::terminal(Error::Upstream {
                provider: "PushGo Token Service",
                status: status.as_u16(),
                message: "token service response missing token".to_string(),
            })
        })?;

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

impl FetchFailure {
    fn terminal(error: Error) -> Self {
        Self {
            error,
            retryable: false,
            retry_after: None,
        }
    }
}

impl RefreshCoordinator {
    fn record_failure(&mut self, error: &Error, retry_after: Option<Duration>) {
        let Error::Upstream { status, .. } = error else {
            return;
        };
        if matches!(*status, 401 | 403) {
            self.terminal_auth_status = Some(*status);
            self.failure_backoff = None;
            return;
        }
        let delay = retry_after
            .unwrap_or_else(|| jittered_backoff(TOKEN_SERVICE_FAILURE_BACKOFF))
            .min(TOKEN_SERVICE_MAX_RETRY_AFTER);
        let until = Instant::now()
            .checked_add(delay)
            .unwrap_or_else(Instant::now);
        self.failure_backoff = Some(FailureBackoff {
            until,
            status: *status,
        });
    }
}

fn jittered_backoff(base: Duration) -> Duration {
    let jitter_window_millis = u64::try_from(base.as_millis() / 2).unwrap_or(u64::MAX);
    let jitter_millis = if jitter_window_millis == 0 {
        0
    } else {
        rand::random::<u64>() % jitter_window_millis.saturating_add(1)
    };
    backoff_with_jitter_sample(base, jitter_millis)
}

fn backoff_with_jitter_sample(base: Duration, jitter_millis: u64) -> Duration {
    let jitter_window_millis = u64::try_from(base.as_millis() / 2).unwrap_or(u64::MAX);
    base.saturating_add(Duration::from_millis(
        jitter_millis.min(jitter_window_millis),
    ))
}

fn parse_retry_after(value: &HeaderValue) -> Option<Duration> {
    let raw = value.to_str().ok()?.trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds).min(TOKEN_SERVICE_MAX_RETRY_AFTER));
    }
    let target = DateTime::parse_from_rfc2822(raw).ok()?.with_timezone(&Utc);
    let delay = (target - Utc::now()).to_std().ok()?;
    Some(delay.min(TOKEN_SERVICE_MAX_RETRY_AFTER))
}

fn token_service_error_from_status(status: u16) -> Error {
    let message = StatusCode::from_u16(status)
        .map(token_service_status_message)
        .unwrap_or("token service request failed");
    Error::Upstream {
        provider: "PushGo Token Service",
        status,
        message: message.to_string(),
    }
}

fn validated_expiry(expires_in: u64) -> Result<Instant, Error> {
    let ttl = Duration::from_secs(expires_in);
    if ttl.is_zero() || ttl > TOKEN_MAX_TTL {
        return Err(Error::Upstream {
            provider: "PushGo Token Service",
            status: 200,
            message: "token service returned an invalid token lifetime".to_string(),
        });
    }
    Instant::now()
        .checked_add(ttl)
        .ok_or_else(|| Error::Upstream {
            provider: "PushGo Token Service",
            status: 200,
            message: "token service returned an invalid token lifetime".to_string(),
        })
}

fn token_service_status_is_retryable(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn token_service_status_message(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "token service authentication failed",
        StatusCode::FORBIDDEN => "token service authorization denied",
        StatusCode::TOO_MANY_REQUESTS => "token service rate limit exceeded",
        _ => "token service request failed",
    }
}

fn observe_token_service_failure(
    provider: GatewayProvider,
    status: StatusCode,
    details: Option<&GatewayErrorPayload>,
    header_request_id: Option<&str>,
) {
    if status.is_success() && details.is_none() {
        return;
    }
    let code = details.and_then(GatewayErrorPayload::safe_code);
    let request_id = details
        .and_then(GatewayErrorPayload::safe_request_id)
        .or(header_request_id);
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "token_service.request_failed",
        provider = provider.as_str(),
        status = status.as_u16(),
        error_code = code.unwrap_or("unknown"),
        upstream_request_id = request_id.unwrap_or("unknown")
    );
}

fn safe_observation_value(raw: &str) -> Option<&str> {
    (!raw.is_empty()
        && raw.len() <= 128
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(raw)
}

#[derive(Deserialize)]
struct GatewayResponse<T> {
    success: bool,
    data: Option<T>,
}

#[derive(Deserialize)]
struct GatewayErrorEnvelope {
    error: Option<GatewayErrorPayload>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GatewayErrorPayload {
    Structured {
        code: Option<String>,
        request_id: Option<String>,
    },
    Legacy(String),
}

impl GatewayErrorPayload {
    fn safe_code(&self) -> Option<&str> {
        match self {
            Self::Structured { code, .. } => code.as_deref().and_then(safe_observation_value),
            Self::Legacy(value) => safe_observation_value(value),
        }
    }

    fn safe_request_id(&self) -> Option<&str> {
        match self {
            Self::Structured { request_id, .. } => {
                request_id.as_deref().and_then(safe_observation_value)
            }
            Self::Legacy(_) => None,
        }
    }
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
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use futures_util::future::join_all;
    use reqwest::header::HeaderValue;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use pushgo_gateway::Error;

    use super::{
        GatewayProvider, GatewayTokenCache, GatewayTokenState, RefreshCoordinator, TOKEN_MAX_TTL,
        TOKEN_SERVICE_MAX_RETRY_AFTER, backoff_with_jitter_sample, build_token_service_http_client,
        parse_retry_after,
    };

    #[derive(Clone)]
    struct TestReply {
        status: &'static str,
        body: String,
        headers: Vec<(String, String)>,
        delay: Duration,
        disconnect_before_response: bool,
    }

    impl TestReply {
        fn token(token: &str, project: &str, expires_in: u64) -> Self {
            Self {
                status: "200 OK",
                body: format!(
                    r#"{{"success":true,"data":{{"token":"{token}","expires_in":{expires_in},"project_id":"{project}"}}}}"#
                ),
                headers: Vec::new(),
                delay: Duration::ZERO,
                disconnect_before_response: false,
            }
        }

        fn error(status: &'static str, code: &str) -> Self {
            Self {
                status,
                body: format!(
                    r#"{{"success":false,"error":{{"code":"{code}","request_id":"test-request"}}}}"#
                ),
                headers: vec![("X-Request-ID".to_string(), "test-request".to_string())],
                delay: Duration::ZERO,
                disconnect_before_response: false,
            }
        }

        fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        fn disconnect_before_response(mut self) -> Self {
            self.disconnect_before_response = true;
            self
        }
    }

    #[tokio::test]
    async fn fresh_token_info_with_project_bypasses_cached_token() {
        let (base_url, request_count, _) = spawn_token_service(vec![
            TestReply::token("token-1", "project-1", 3600),
            TestReply::token("token-2", "project-2", 3600),
        ])
        .await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        );

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

    #[tokio::test]
    async fn token_request_is_sent_without_authorization() {
        let (base_url, _, requests) =
            spawn_token_service(vec![TestReply::token("token", "project", 3600)]).await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        );

        cache
            .token_info_with_project_fresh()
            .await
            .expect("unauthenticated request should succeed");

        let captured = requests.lock().expect("captured requests lock");
        assert!(
            !captured[0]
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        );
    }

    #[tokio::test]
    async fn unauthorized_response_is_not_retried() {
        let unauthorized = TestReply::error("401 Unauthorized", "authentication_failed")
            .with_header("WWW-Authenticate", "Bearer");
        let (base_url, request_count, _) = spawn_token_service(vec![
            unauthorized.clone(),
            unauthorized.clone(),
            unauthorized,
        ])
        .await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Wns,
            &base_url,
        );

        let error = cache
            .token_info_fresh()
            .await
            .expect_err("authentication failure must be terminal");

        assert!(matches!(error, Error::Upstream { status: 401, .. }));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn forbidden_response_is_not_retried() {
        let forbidden = TestReply::error("403 Forbidden", "authorization_denied");
        let (base_url, request_count, _) =
            spawn_token_service(vec![forbidden.clone(), forbidden.clone(), forbidden]).await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Wns,
            &base_url,
        );

        let error = cache
            .token_info_fresh()
            .await
            .expect_err("authorization failure must be terminal");

        assert!(matches!(error, Error::Upstream { status: 403, .. }));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn transient_response_retries_then_succeeds() {
        let (base_url, request_count, _) = spawn_token_service(vec![
            TestReply::error("503 Service Unavailable", "provider_unavailable"),
            TestReply::token("recovered", "project", 3600),
        ])
        .await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        );

        let (token, _) = cache
            .token_info_with_project_fresh()
            .await
            .expect("second attempt should recover");

        assert_eq!(&*token.token, "recovered");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn response_header_eof_is_retried_for_idempotent_get() {
        let (base_url, request_count, _) = spawn_token_service(vec![
            TestReply::token("discarded", "project", 3600).disconnect_before_response(),
            TestReply::token("recovered", "project", 3600),
        ])
        .await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        );

        let (token, _) = cache
            .token_info_with_project_fresh()
            .await
            .expect("connection reset before response headers should be retried");

        assert_eq!(&*token.token, "recovered");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn transient_response_retry_count_is_bounded() {
        let unavailable = TestReply::error("503 Service Unavailable", "provider_unavailable");
        let (base_url, request_count, _) =
            spawn_token_service(vec![unavailable.clone(), unavailable.clone(), unavailable]).await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Apns,
            &base_url,
        );

        let error = cache
            .token_info_fresh()
            .await
            .expect_err("retry budget should eventually fail");

        assert!(matches!(error, Error::Upstream { status: 503, .. }));
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn failed_refresh_rechecks_cache_expiry_after_await() {
        let unauthorized = TestReply::error("401 Unauthorized", "authentication_failed")
            .with_delay(Duration::from_millis(50));
        let (base_url, _, _) = spawn_token_service(vec![unauthorized]).await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Wns,
            &base_url,
        );
        cache.state.store(Arc::new(GatewayTokenState {
            token: Arc::from("almost-expired"),
            expires_at: Instant::now() + Duration::from_millis(10),
            project_id: None,
            generation: 1,
        }));

        let error = cache
            .token_info()
            .await
            .expect_err("expired cache must not be returned after refresh await");

        assert!(matches!(error, Error::Upstream { status: 401, .. }));
    }

    #[tokio::test]
    async fn cross_origin_redirect_is_rejected_without_contacting_target() {
        let (target_url, target_count, _) =
            spawn_token_service(vec![TestReply::token("stolen", "project", 3600)]).await;
        let redirect = TestReply {
            status: "302 Found",
            body: String::new(),
            headers: vec![(
                "Location".to_string(),
                format!("{target_url}/provider/token?provider=fcm"),
            )],
            delay: Duration::ZERO,
            disconnect_before_response: false,
        };
        let (base_url, source_count, _) = spawn_token_service(vec![redirect]).await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        );

        cache
            .token_info_with_project_fresh()
            .await
            .expect_err("cross-origin redirect must fail");

        assert_eq!(source_count.load(Ordering::SeqCst), 1);
        assert_eq!(target_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn concurrent_explicit_refresh_uses_one_request_and_one_generation() {
        let reply =
            TestReply::token("singleflight", "project", 3600).with_delay(Duration::from_millis(50));
        let (base_url, request_count, _) = spawn_token_service(vec![reply]).await;
        let cache = Arc::new(GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        ));

        let results = join_all((0..64).map(|_| {
            let cache = Arc::clone(&cache);
            async move { cache.token_info_with_project_fresh().await }
        }))
        .await;

        assert!(results.iter().all(|result| result.is_ok()));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        assert_eq!(cache.state.load().generation, 1);
    }

    #[tokio::test]
    async fn delayed_refresh_cannot_be_overtaken_or_overwrite_a_newer_generation() {
        let (base_url, request_count, _) = spawn_token_service(vec![
            TestReply::token("first-generation", "project", 3600)
                .with_delay(Duration::from_millis(100)),
            TestReply::token("second-generation", "project", 3600),
        ])
        .await;
        let cache = Arc::new(GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        ));

        let first = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { cache.token_info_with_project_fresh().await })
        };
        wait_for_request_count(&request_count, 1).await;
        let second = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { cache.token_info_with_project_fresh().await })
        };

        let (first, _) = first
            .await
            .expect("first refresh task should join")
            .expect("first refresh should succeed");
        let (second, _) = second
            .await
            .expect("second refresh task should join")
            .expect("waiting refresh should reuse the completed generation");

        assert_eq!(&*first.token, "first-generation");
        assert_eq!(&*second.token, "first-generation");
        assert_eq!(&*cache.state.load().token, "first-generation");
        assert_eq!(cache.state.load().generation, 1);
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        let (next, _) = cache
            .token_info_with_project_fresh()
            .await
            .expect("a later explicit refresh should create the next generation");
        assert_eq!(&*next.token, "second-generation");
        assert_eq!(cache.state.load().generation, 2);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_authentication_failures_open_one_shared_circuit() {
        let unauthorized = TestReply::error("401 Unauthorized", "authentication_failed")
            .with_delay(Duration::from_millis(50));
        let (base_url, request_count, _) = spawn_token_service(vec![unauthorized]).await;
        let cache = Arc::new(GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Wns,
            &base_url,
        ));

        let results = join_all((0..64).map(|_| {
            let cache = Arc::clone(&cache);
            async move { cache.token_info_fresh().await }
        }))
        .await;
        let later = cache
            .token_info_fresh()
            .await
            .expect_err("authentication circuit must remain open");

        assert!(results.iter().all(|result| result.is_err()));
        assert!(matches!(later, Error::Upstream { status: 401, .. }));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn transient_failure_backoff_is_shared_across_waiters() {
        let unavailable = TestReply::error("503 Service Unavailable", "provider_unavailable");
        let (base_url, request_count, _) =
            spawn_token_service(vec![unavailable.clone(), unavailable.clone(), unavailable]).await;
        let cache = Arc::new(GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Apns,
            &base_url,
        ));

        cache
            .token_info_fresh()
            .await
            .expect_err("initial transient failure should exhaust its request budget");
        let results = join_all((0..64).map(|_| {
            let cache = Arc::clone(&cache);
            async move { cache.token_info_fresh().await }
        }))
        .await;

        assert!(results.iter().all(|result| result.is_err()));
        assert_eq!(request_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retry_after_delta_seconds_is_parsed_and_bounded() {
        let value = HeaderValue::from_static("999");
        assert_eq!(
            parse_retry_after(&value),
            Some(TOKEN_SERVICE_MAX_RETRY_AFTER)
        );
    }

    #[test]
    fn default_backoff_jitter_is_deterministically_bounded() {
        let base = Duration::from_millis(200);
        assert_eq!(backoff_with_jitter_sample(base, 0), base);
        assert_eq!(
            backoff_with_jitter_sample(base, u64::MAX),
            Duration::from_millis(300)
        );
    }

    #[test]
    fn refresh_coordinator_uses_retry_after_for_shared_backoff() {
        let mut coordinator = RefreshCoordinator::default();
        let error = Error::Upstream {
            provider: "PushGo Token Service",
            status: 429,
            message: "token service rate limit exceeded".to_string(),
        };

        coordinator.record_failure(&error, Some(Duration::from_secs(4)));

        let remaining = coordinator
            .failure_backoff
            .expect("retryable failure should set shared backoff")
            .until
            .saturating_duration_since(Instant::now());
        assert!(remaining >= Duration::from_secs(3));
    }

    #[tokio::test]
    async fn invalid_protocol_response_opens_shared_cooldown_for_all_waiters() {
        let reply = TestReply::token("invalid-lifetime", "project", TOKEN_MAX_TTL.as_secs() + 1)
            .with_delay(Duration::from_millis(50));
        let (base_url, request_count, _) = spawn_token_service(vec![reply]).await;
        let cache = Arc::new(GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        ));

        let results = join_all((0..64).map(|_| {
            let cache = Arc::clone(&cache);
            async move { cache.token_info_with_project_fresh().await }
        }))
        .await;
        let later = cache
            .token_info_with_project_fresh()
            .await
            .expect_err("protocol cooldown should fail fast");

        assert!(results.iter().all(|result| result.is_err()));
        assert!(matches!(later, Error::Upstream { status: 200, .. }));
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        assert_eq!(cache.state.load().generation, 0);
    }

    #[tokio::test]
    async fn token_lifetime_above_cache_limit_is_rejected() {
        let (base_url, _, _) = spawn_token_service(vec![TestReply::token(
            "token",
            "project",
            TOKEN_MAX_TTL.as_secs() + 1,
        )])
        .await;
        let cache = GatewayTokenCache::new(
            build_token_service_http_client().expect("test client should build"),
            GatewayProvider::Fcm,
            &base_url,
        );

        let error = cache
            .token_info_with_project_fresh()
            .await
            .expect_err("unbounded cache lifetime must fail");

        assert!(error.to_string().contains("invalid token lifetime"));
    }

    async fn spawn_token_service(
        replies: Vec<TestReply>,
    ) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
        assert!(
            !replies.is_empty(),
            "test server requires at least one reply"
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener addr should exist");
        let request_count = Arc::new(AtomicUsize::new(0));
        let served_count = Arc::clone(&request_count);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&requests);
        tokio::spawn(async move {
            for reply in replies {
                let (mut socket, _) = listener.accept().await.expect("request should accept");
                let mut request_bytes = Vec::with_capacity(1024);
                loop {
                    let mut buffer = [0u8; 1024];
                    let read = socket.read(&mut buffer).await.expect("request should read");
                    if read == 0 {
                        break;
                    }
                    request_bytes.extend_from_slice(&buffer[..read]);
                    if request_bytes.windows(4).any(|window| window == b"\r\n\r\n")
                        || request_bytes.len() >= 16 * 1024
                    {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request_bytes).into_owned();
                captured_requests
                    .lock()
                    .expect("captured request lock")
                    .push(request);
                served_count.fetch_add(1, Ordering::SeqCst);
                if !reply.delay.is_zero() {
                    tokio::time::sleep(reply.delay).await;
                }
                if reply.disconnect_before_response {
                    continue;
                }
                let extra_headers = reply
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}\r\n"))
                    .collect::<String>();
                let response = format!(
                    "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{}connection: close\r\n\r\n{}",
                    reply.status,
                    reply.body.len(),
                    extra_headers,
                    reply.body
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("response should write");
            }
        });
        (format!("http://{addr}"), request_count, requests)
    }

    async fn wait_for_request_count(request_count: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while request_count.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test server should receive the request");
    }
}
