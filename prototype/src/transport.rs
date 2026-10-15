//! Ordinary FCM/APNs only, using synthetic credentials and loopback HTTP.
//! Existing Gateway token owners can be injected; the fixture connects only to
//! explicit synthetic loopback endpoints. Oversize ordinary payloads
//! use a bounded wakeup projection; their Pull copy already lives in the ledger.
use crate::{
    ProviderTransport,
    credentials::{CredentialProvider, ExistingTokenCredentials, FixtureCredentials},
    store::{KernelError, now},
    types::Platform,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    Transport,
    RateLimited,
    TemporarilyUnavailable,
    InvalidToken,
    PayloadTooLarge,
    Unauthorized,
    ProviderAccessFailed,
    CredentialsExpired,
    Rejected,
}
impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::RateLimited => "rate_limited",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::PayloadTooLarge => "payload_too_large",
            Self::Unauthorized => "unauthorized",
            Self::ProviderAccessFailed => "provider_access_failed",
            Self::CredentialsExpired => "credentials_expired",
            Self::Rejected => "rejected",
        }
    }
}
#[derive(Debug)]
pub struct DispatchResult {
    pub success: bool,
    pub status_code: u16,
    pub failure_kind: Option<FailureKind>,
    pub retry_after_millis: Option<i64>,
}
impl DispatchResult {
    pub fn success(status_code: u16) -> Self {
        Self {
            success: true,
            status_code,
            failure_kind: None,
            retry_after_millis: None,
        }
    }
    fn failure(status_code: u16, kind: FailureKind, retry: Option<i64>) -> Self {
        Self {
            success: false,
            status_code,
            failure_kind: Some(kind),
            retry_after_millis: retry,
        }
    }
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.failure_kind,
            Some(
                FailureKind::ProviderAccessFailed
                    | FailureKind::CredentialsExpired
                    | FailureKind::Transport
                    | FailureKind::RateLimited
                    | FailureKind::TemporarilyUnavailable
            )
        )
    }
    pub fn failure_kind_name(&self) -> &'static str {
        self.failure_kind.map(FailureKind::as_str).unwrap_or("none")
    }
}
pub struct RealProviders {
    clients: [Mutex<Option<reqwest::Client>>; 2],
    fcm_endpoint: Arc<str>,
    apns_endpoint: Arc<str>,
    transport_errors: AtomicUsize,
    oversized_responses: AtomicUsize,
    idle_budget: usize,
    credentials: Arc<dyn CredentialProvider>,
    apns_topic: Arc<str>,
}
impl RealProviders {
    pub fn loopback(endpoint: &str) -> Result<Self, KernelError> {
        Self::loopback_with_budget(endpoint, crate::Config::default().provider_budget)
    }
    pub fn loopback_with_budget(endpoint: &str, idle_budget: usize) -> Result<Self, KernelError> {
        Self::loopback_with_credentials(
            endpoint,
            idle_budget,
            Arc::new(FixtureCredentials),
            Arc::from("io.ethan.pushgo"),
        )
    }
    pub fn loopback_with_credentials(
        endpoint: &str,
        idle_budget: usize,
        credentials: Arc<dyn CredentialProvider>,
        apns_topic: Arc<str>,
    ) -> Result<Self, KernelError> {
        let url = reqwest::Url::parse(endpoint)
            .map_err(|_| KernelError::Invalid("provider endpoint".into()))?;
        let ip = url
            .host_str()
            .and_then(|value| value.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        if url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || !ip.is_some_and(|ip| ip.is_loopback())
            || url.port().is_none_or(|port| port == 0)
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(KernelError::Invalid(
                "loopback HTTP endpoint with explicit port required".into(),
            ));
        }
        Self::with_validated_endpoints(endpoint, endpoint, idle_budget, credentials, apns_topic)
    }

    /// Configure ordinary provider HTTPS origins with existing production token
    /// owners. Construction performs no I/O and never reads configuration.
    pub fn configured(
        fcm_endpoint: &str,
        apns_endpoint: &str,
        idle_budget: usize,
        fcm_tokens: Arc<dyn pushgo_gateway::providers::FcmTokenProvider>,
        apns_tokens: Arc<dyn pushgo_gateway::providers::ApnsTokenProvider>,
        apns_topic: Arc<str>,
    ) -> Result<Self, KernelError> {
        for endpoint in [fcm_endpoint, apns_endpoint] {
            let url = reqwest::Url::parse(endpoint)
                .map_err(|_| KernelError::Invalid("provider HTTPS origin required".into()))?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port() == Some(0)
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(KernelError::Invalid(
                    "provider HTTPS origin required".into(),
                ));
            }
        }
        Self::with_validated_endpoints(
            fcm_endpoint,
            apns_endpoint,
            idle_budget,
            Arc::new(ExistingTokenCredentials::new(fcm_tokens, apns_tokens)),
            apns_topic,
        )
    }

    fn with_validated_endpoints(
        fcm_endpoint: &str,
        apns_endpoint: &str,
        idle_budget: usize,
        credentials: Arc<dyn CredentialProvider>,
        apns_topic: Arc<str>,
    ) -> Result<Self, KernelError> {
        if apns_topic.is_empty()
            || apns_topic.len() > 255
            || !apns_topic
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b".-".contains(&v))
        {
            return Err(KernelError::Invalid("invalid APNs topic".into()));
        }
        if idle_budget == 0 {
            return Err(KernelError::Invalid(
                "positive provider connection budget required".into(),
            ));
        }
        Ok(Self {
            clients: [Mutex::new(None), Mutex::new(None)],
            fcm_endpoint: Arc::from(fcm_endpoint.trim_end_matches('/')),
            apns_endpoint: Arc::from(apns_endpoint.trim_end_matches('/')),
            transport_errors: AtomicUsize::new(0),
            oversized_responses: AtomicUsize::new(0),
            idle_budget,
            credentials,
            apns_topic,
        })
    }
    fn client(&self, provider: &str) -> Result<reqwest::Client, reqwest::Error> {
        let index = usize::from(provider == "APNS");
        let mut slot = self.clients[index].lock().unwrap();
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }
        // Retain the bounded provider window during continuous work, avoiding
        // TCP churn. Its pump releases this owner on proven quiescence instead
        // of adding an idle-pool timer. Each HTTP future owns its own clone.
        // A configured origin remains authoritative; a provider response must
        // not redirect credentials or downgrade the validated HTTPS boundary.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(self.idle_budget)
            .pool_idle_timeout(None)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent("free-delivery-prototype/0.1")
            .build()?;
        *slot = Some(client.clone());
        Ok(client)
    }
    pub fn transport_errors(&self) -> usize {
        self.transport_errors.load(Ordering::Relaxed)
    }
    pub fn oversized_responses(&self) -> usize {
        self.oversized_responses.load(Ordering::Relaxed)
    }
    pub fn resource_snapshot(&self) -> Value {
        let owners: Vec<bool> = self
            .clients
            .iter()
            .map(|slot| slot.lock().unwrap().is_some())
            .collect();
        json!({"provider_client_owners":owners,"idle_connections_per_provider_limit":self.idle_budget})
    }
    fn record_transport_error(&self, provider: &str, phase: &str, error: &reqwest::Error) {
        let count = self.transport_errors.fetch_add(1, Ordering::Relaxed) + 1;
        if count > 16 {
            return;
        }
        let mut io = Vec::new();
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
        for _ in 0..8 {
            let Some(current) = source else {
                break;
            };
            if let Some(error) = current.downcast_ref::<std::io::Error>() {
                io.push((error.kind(), error.raw_os_error()));
            }
            source = current.source();
        }
        // Do not print Error/Display/source messages: they may contain URL,
        // headers or payload. Only bounded categorical diagnostics are kept.
        eprintln!(
            "TRANSPORT_ERROR sample={count} provider={provider} phase={phase} timeout={} connect={} body={} request={} io={io:?}",
            error.is_timeout(),
            error.is_connect(),
            error.is_body(),
            error.is_request()
        );
    }
    #[allow(clippy::too_many_arguments)] // Fields mirror the preserved delivery ticket boundary.
    async fn request(
        &self,
        provider: &str,
        platform: Platform,
        token: &str,
        payload: Value,
        delivery: &str,
        device: &str,
        accepted: i64,
        expiry: i64,
    ) -> DispatchResult {
        let mut data = BTreeMap::<String, String>::new();
        if let Some(object) = payload.as_object() {
            for (key, value) in object {
                if let Some(value) = value.as_str() {
                    data.insert(key.clone(), value.to_owned());
                }
            }
        }
        // base_url is supplied by canonical ledger acceptance, never Host or
        // sender custom data. Missing authority must not produce un-ACKable data.
        if data.get("base_url").is_none_or(|value| value.is_empty()) {
            return DispatchResult::failure(0, FailureKind::Rejected, None);
        }
        data.insert("delivery_id".into(), delivery.into());
        data.insert("provider_device_key".into(), device.into());
        data.insert("sent_at".into(), accepted.to_string());
        // Canonical optional TTL is absolute milliseconds. Provider envelope
        // TTL/expiration below uses its own required units without changing data.
        let fcm = provider == "FCM" && platform == Platform::Android;
        let apns = provider == "APNS" && matches!(platform, Platform::Ios | Platform::Macos);
        if !fcm && !apns {
            return DispatchResult::failure(0, FailureKind::Rejected, None);
        }
        let fcm_priority = if data.get("severity").is_some_and(|v| v == "low") {
            "NORMAL"
        } else {
            "HIGH"
        };
        let encode = |data: &BTreeMap<String, String>| {
            let value = if fcm {
                json!({"message":{"token":token,"data":data,"android":{"priority":fcm_priority,"ttl":format!("{}s",(expiry.saturating_sub(now())/1000).clamp(0, 28 * 86_400))}}})
            } else {
                apns_body(data)
            };
            serde_json::to_vec(&value)
        };
        let mut body = match encode(&data) {
            Ok(body) => body,
            Err(_) => return DispatchResult::failure(0, FailureKind::Rejected, None),
        };
        // Count the exact serialized bytes submitted, including JSON escaping
        // and provider envelope, rather than estimating raw string lengths.
        if body.len() > 4096 {
            body = match encode(&wakeup_data(&data)) {
                Ok(body) if body.len() <= 4096 => body,
                _ => return DispatchResult::failure(0, FailureKind::PayloadTooLarge, None),
            };
        }
        let client = match self.client(provider) {
            Ok(client) => client,
            Err(error) => {
                self.record_transport_error(provider, "client", &error);
                return DispatchResult::failure(0, FailureKind::Transport, None);
            }
        };
        let (access_token, project_id) = if fcm {
            match self.credentials.fcm(false).await {
                Ok(value) => (value.access_token, Some(value.project_id)),
                Err(_) => {
                    return DispatchResult::failure(0, FailureKind::ProviderAccessFailed, None);
                }
            }
        } else {
            match self.credentials.apns(false).await {
                Ok(value) => (value.access_token, None),
                Err(_) => {
                    return DispatchResult::failure(0, FailureKind::ProviderAccessFailed, None);
                }
            }
        };
        let request = if fcm {
            client.post(format!(
                "{}/v1/projects/{}/messages:send",
                self.fcm_endpoint,
                project_id.as_deref().unwrap()
            ))
        } else {
            client
                .post(format!("{}/3/device/{}", self.apns_endpoint, token))
                .header("apns-topic", self.apns_topic.as_ref())
                .header("apns-push-type", "alert")
                .header("apns-priority", "10")
                .header("apns-expiration", expiry.div_euclid(1000).to_string())
        }
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body);
        // Serialization now owns the wire bytes; full business payload copies
        // are unnecessary while the network response/receipt is pending.
        drop(data);
        drop(payload);
        let mut response = match request.bearer_auth(access_token.as_ref()).send().await {
            Ok(response) => response,
            Err(error) => {
                self.record_transport_error(provider, "send", &error);
                return DispatchResult::failure(0, FailureKind::Transport, None);
            }
        };
        let status = response.status().as_u16();
        let retry = parse_retry_after(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
        );
        // Provider JSON is diagnostic input, never business payload. Bound the
        // accumulated bytes even when the peer omits/lies about Content-Length.
        // Dropping an oversized body closes/resets that response; it cannot turn
        // an already accepted 2xx into a retry and duplicate the notification.
        const MAX_PROVIDER_RESPONSE_BYTES: usize = 16 * 1024;
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if chunk.len() <= MAX_PROVIDER_RESPONSE_BYTES - body.len() => {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) => {
                    self.oversized_responses.fetch_add(1, Ordering::Relaxed);
                    body.clear();
                    break;
                }
                Ok(None) => break,
                Err(error) => {
                    self.record_transport_error(provider, "body", &error);
                    if (200..300).contains(&status) {
                        return DispatchResult::success(status);
                    }
                    return self
                        .classify_and_refresh(provider, status, &body, retry)
                        .await;
                }
            }
        }
        if (200..300).contains(&status) {
            return DispatchResult::success(status);
        }
        self.classify_and_refresh(provider, status, &body, retry)
            .await
    }
    async fn classify_and_refresh(
        &self,
        provider: &str,
        status: u16,
        body: &[u8],
        retry: Option<i64>,
    ) -> DispatchResult {
        let result = classify(provider, status, body, retry);
        if result.failure_kind == Some(FailureKind::CredentialsExpired) {
            // Prepare the shared cache for the next durable attempt; never resend inline.
            if provider == "FCM" {
                let _ = self.credentials.fcm(true).await;
            } else {
                let _ = self.credentials.apns(true).await;
            }
        }
        result
    }
}
impl ProviderTransport for RealProviders {
    fn quiesce(&self, provider: &str) {
        let index = usize::from(provider == "APNS");
        let idle = self.clients[index].lock().unwrap().take();
        drop(idle);
    }
    fn send<'a>(
        &'a self,
        provider: &'a str,
        platform: Platform,
        token: &'a str,
        payload: Value,
        delivery: &'a str,
        device: &'a str,
        accepted: i64,
        expiry: i64,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(self.request(
            provider, platform, token, payload, delivery, device, accepted, expiry,
        ))
    }
}
fn apns_body(data: &BTreeMap<String, String>) -> Value {
    let mut body = serde_json::Map::new();
    for (key, value) in data {
        body.insert(key.clone(), Value::String(value.clone()));
    }
    let mut alert = serde_json::Map::new();
    for key in ["title", "body"] {
        if let Some(value) = data.get(key).map(|v| v.trim()).filter(|v| !v.is_empty()) {
            alert.insert(key.into(), Value::String(value.into()));
        }
    }
    if alert.is_empty() {
        alert.insert("body".into(), Value::String("Message".into()));
    }
    let mut aps = json!({"alert":alert,"mutable-content":1});
    if data.get("provider_mode").map(String::as_str) != Some("wakeup") {
        let level = match data.get("severity").map(String::as_str) {
            Some("critical") => "critical",
            Some("high") => "time-sensitive",
            Some("low") => "passive",
            _ => "active",
        };
        aps["interruption-level"] = Value::String(level.into());
    }
    body.insert("aps".into(), aps);
    Value::Object(body)
}
fn wakeup_data(data: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut wakeup = BTreeMap::new();
    for key in [
        "delivery_id",
        "provider_device_key",
        "channel_id",
        "entity_type",
        "entity_id",
        "message_id",
        "event_id",
        "thing_id",
        "op_id",
        "sent_at",
        "ttl",
        "schema_version",
        "payload_version",
        "base_url",
    ] {
        if let Some(value) = data.get(key) {
            wakeup.insert(key.into(), value.clone());
        }
    }
    // The recovery hint remains small even for a sender's very long title/body.
    for (key, max) in [("title", 80), ("body", 180)] {
        if let Some(value) = data.get(key) {
            wakeup.insert(key.into(), value.chars().take(max).collect());
        }
    }
    wakeup.insert("provider_mode".into(), "wakeup".into());
    wakeup.insert("provider_wakeup".into(), "1".into());
    wakeup.insert("_skip_persist".into(), "1".into());
    wakeup
}
fn parse_retry_after(raw: Option<&str>) -> Option<i64> {
    let raw = raw?.trim();
    let max = 86_400_000;
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some((seconds.min(86_400) * 1000) as i64);
    }
    let date = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    let delay = date.timestamp_millis().saturating_sub(now());
    (delay > 0).then_some(delay.min(max))
}
fn classify(provider: &str, status: u16, body: &[u8], retry: Option<i64>) -> DispatchResult {
    let json: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let reason = json.get("reason").and_then(Value::as_str).unwrap_or("");
    if provider == "FCM" {
        let error = json.get("error").filter(|v| v.is_object());
        let text = error
            .and_then(|v| v.get("message"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| {
                if error.is_none() {
                    String::from_utf8_lossy(body).to_ascii_lowercase()
                } else {
                    String::new()
                }
            });
        let invalid = error
            .and_then(|v| v.get("status"))
            .and_then(Value::as_str)
            .is_some_and(|v| v.eq_ignore_ascii_case("NOT_FOUND"))
            || error
                .and_then(|v| v.get("details"))
                .and_then(Value::as_array)
                .is_some_and(|details| {
                    details.iter().any(|d| {
                        d.get("errorCode")
                            .and_then(Value::as_str)
                            .is_some_and(|v| v.eq_ignore_ascii_case("UNREGISTERED"))
                    })
                })
            || text.contains("unregistered")
            || text.contains("not registered")
            || text.contains("invalid registration token")
            || (text.contains("registration token") && text.contains("invalid"));
        if invalid {
            return DispatchResult::failure(status, FailureKind::InvalidToken, retry);
        }
        if status == 400
            && error
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
                .is_some_and(|v| v.eq_ignore_ascii_case("INVALID_ARGUMENT"))
            && text.contains("message too big")
        {
            return DispatchResult::failure(status, FailureKind::PayloadTooLarge, retry);
        }
    }
    if status == 429 {
        return DispatchResult::failure(
            status,
            FailureKind::RateLimited,
            Some(retry.unwrap_or(0).max(60_000)),
        );
    }
    if status == 408 || (500..600).contains(&status) {
        let floor = if provider == "APNS" { 900_000 } else { 10_000 };
        return DispatchResult::failure(
            status,
            FailureKind::TemporarilyUnavailable,
            Some(retry.unwrap_or(0).max(floor)),
        );
    }
    if provider == "APNS" && matches!(status, 401 | 403) && reason == "ExpiredProviderToken" {
        return DispatchResult::failure(status, FailureKind::CredentialsExpired, retry);
    }
    let invalid = if provider == "APNS" {
        status == 410
            || matches!(
                reason,
                "BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered"
            )
    } else {
        false
    };
    let kind = if invalid {
        FailureKind::InvalidToken
    } else if status == 413 {
        FailureKind::PayloadTooLarge
    } else if provider == "FCM" && matches!(status, 401 | 403) {
        FailureKind::CredentialsExpired
    } else if matches!(status, 401 | 403) {
        FailureKind::Unauthorized
    } else {
        FailureKind::Rejected
    };
    DispatchResult::failure(status, kind, retry)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fcm_invalid_token_requires_provider_evidence_and_payload_errors_do_not_retire_routes() {
        assert_eq!(
            classify("FCM", 404, b"", None).failure_kind,
            Some(FailureKind::Rejected)
        );
        assert_eq!(
            classify("FCM", 404, br#"{"error":{"status":"NOT_FOUND"}}"#, None).failure_kind,
            Some(FailureKind::InvalidToken)
        );
        assert_eq!(
            classify(
                "FCM",
                400,
                br#"{"error":{"status":"INVALID_ARGUMENT","message":"Message too big"}}"#,
                None
            )
            .failure_kind,
            Some(FailureKind::PayloadTooLarge)
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn provider_pool_reuses_connections_and_quiesce_preserves_held_request() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;
        let peers = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let handler_peers = peers.clone();
        let handler_started = started.clone();
        let handler_release = release.clone();
        let app = axum::Router::new().route(
            "/v1/projects/fixture-project/messages:send",
            axum::routing::post(
                move |ConnectInfo(peer): ConnectInfo<SocketAddr>,
                      axum::Json(_body): axum::Json<Value>| {
                    let peers = handler_peers.clone();
                    let started = handler_started.clone();
                    let release = handler_release.clone();
                    async move {
                        let first = {
                            let mut peers = peers.lock().unwrap();
                            peers.push(peer);
                            peers.len() == 1
                        };
                        if first {
                            started.notify_one();
                            release.notified().await;
                        }
                        axum::Json(json!({"name":"synthetic receipt"}))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let provider = Arc::new(RealProviders::loopback(&endpoint).unwrap());
        assert!(
            provider
                .clients
                .iter()
                .all(|slot| slot.lock().unwrap().is_none())
        );
        let other_provider_client = provider.client("APNS").unwrap();
        let sending = provider.clone();
        let held = tokio::spawn(async move {
            let accepted = now();
            sending
                .request(
                    "FCM",
                    Platform::Android,
                    "synthetic-token",
                    json!({"base_url":"https://fixture.invalid","body":"held"}),
                    "held-delivery",
                    "held-device",
                    accepted,
                    accepted + 60_000,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(3), started.notified())
            .await
            .unwrap();
        assert!(provider.clients[0].lock().unwrap().is_some());
        provider.quiesce("FCM");
        assert!(provider.clients[0].lock().unwrap().is_none());
        assert!(provider.clients[1].lock().unwrap().is_some());
        assert!(!held.is_finished());
        release.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), held)
                .await
                .unwrap()
                .unwrap()
                .success
        );
        // A new lazy pool is retained across ordinary sequential batches. The
        // observed peer port establishes real TCP reuse, not just Client clones.
        for n in 0..6 {
            let accepted = now();
            assert!(
                provider
                    .request(
                        "FCM",
                        Platform::Android,
                        "synthetic-token",
                        json!({"base_url":"https://fixture.invalid","body":"next-batch"}),
                        &format!("next-{n}"),
                        "next-device",
                        accepted,
                        accepted + 60_000
                    )
                    .await
                    .success
            );
        }
        {
            let peers = peers.lock().unwrap();
            assert_eq!(peers.len(), 7);
            assert!(peers[1..].iter().all(|peer| *peer == peers[1]));
        }
        assert_eq!(provider.transport_errors(), 0);
        provider.quiesce("FCM");
        assert!(provider.clients[0].lock().unwrap().is_none());
        assert!(provider.clients[1].lock().unwrap().is_some());
        provider.quiesce("APNS");
        drop(other_provider_client);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    #[tokio::test]
    async fn fcm_wire_clips_long_business_expiry_to_provider_limit() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Value>();
        let capture = Arc::new(std::sync::Mutex::new(Some(tx)));
        let app = axum::Router::new().route(
            "/v1/projects/fixture-project/messages:send",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                let capture = capture.clone();
                async move {
                    capture.lock().unwrap().take().unwrap().send(body).unwrap();
                    axum::Json(json!({"name":"projects/fixture-project/messages/local"}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = RealProviders::loopback(&endpoint).unwrap();
        let accepted = now();
        let business_expiry = accepted + 35 * 86_400_000;
        let response = provider.request(
            "FCM", Platform::Android, "synthetic-fcm-token",
            json!({"title":"long-life","body":"synthetic","op_id":"long-life","message_id":"message-one","base_url":"https://fixture.invalid/gateway"}),
            "delivery-one", "device-one", accepted, business_expiry,
        ).await;
        assert!(response.success);
        let wire = rx.await.unwrap();
        assert_eq!(wire["message"]["android"]["ttl"], "2419200s");
        assert_eq!(wire["message"]["data"]["delivery_id"], "delivery-one");
        assert!(wire["message"]["data"].get("ttl").is_none());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    #[tokio::test]
    async fn oversized_serialized_payloads_use_bounded_wakeup_with_frozen_identity() {
        for (provider_name, platform, path) in [
            (
                "FCM",
                Platform::Android,
                "/v1/projects/fixture-project/messages:send",
            ),
            ("APNS", Platform::Ios, "/3/device/synthetic-apns"),
        ] {
            let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
            let capture = Arc::new(std::sync::Mutex::new(Some(tx)));
            let app = axum::Router::new().route(
                path,
                axum::routing::post(move |body: axum::body::Bytes| {
                    let capture = capture.clone();
                    async move {
                        capture
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(body.to_vec())
                            .unwrap();
                        axum::Json(json!({"name":"synthetic receipt"}))
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let provider = RealProviders::loopback(&endpoint).unwrap();
            let accepted = now();
            let expiry = accepted + 3_600_000;
            // Quotes cost twice as many JSON bytes as raw UTF-8 characters.
            let response = provider.request(provider_name, platform, "synthetic-apns",
                json!({"title":"wire","body":"\"".repeat(3000),"message_id":"frozen-message","base_url":"https://fixture.invalid/Prefix","delivery_id":"spoofed","provider_device_key":"spoofed","sent_at":"0","ttl":expiry.to_string()}),
                "frozen-delivery", "frozen-device", accepted, expiry).await;
            assert!(response.success);
            let bytes = rx.await.unwrap();
            assert!(bytes.len() <= 4096);
            let wire: Value = serde_json::from_slice(&bytes).unwrap();
            let data = if provider_name == "FCM" {
                &wire["message"]["data"]
            } else {
                &wire
            };
            assert_eq!(data["provider_mode"], "wakeup");
            assert_eq!(data["provider_wakeup"], "1");
            assert_eq!(data["_skip_persist"], "1");
            assert_eq!(data["delivery_id"], "frozen-delivery");
            assert_eq!(data["provider_device_key"], "frozen-device");
            assert_eq!(data["sent_at"], accepted.to_string());
            assert_eq!(data["ttl"], expiry.to_string());
            assert_eq!(data["base_url"], "https://fixture.invalid/Prefix");
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
    }
    #[tokio::test]
    async fn oversized_provider_responses_preserve_status_and_retry_headers() {
        for (status, success, failure, retry) in [
            (200, true, None, None),
            (429, false, Some(FailureKind::RateLimited), Some(120_000)),
            (
                503,
                false,
                Some(FailureKind::TemporarilyUnavailable),
                Some(120_000),
            ),
            (404, false, Some(FailureKind::Rejected), Some(120_000)),
        ] {
            let app = axum::Router::new().fallback(move || async move {
                axum::http::Response::builder()
                    .status(status)
                    .header("retry-after", "120")
                    .body(axum::body::Body::from(vec![b'x'; 64 * 1024]))
                    .unwrap()
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let provider = RealProviders::loopback(&endpoint).unwrap();
            let accepted = now();
            let result = provider
                .request(
                    "FCM",
                    Platform::Android,
                    "synthetic-token",
                    json!({"base_url":"https://fixture.invalid","body":"small"}),
                    "delivery",
                    "device",
                    accepted,
                    accepted + 60_000,
                )
                .await;
            assert_eq!(result.status_code, status);
            assert_eq!(result.success, success);
            assert_eq!(result.failure_kind, failure);
            assert_eq!(result.retry_after_millis, retry);
            assert_eq!(provider.oversized_responses(), 1);
            assert_eq!(provider.transport_errors(), 0);
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    async fn truncated_provider_response_preserves_received_status_and_retry_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (status, success, failure, retry) in [
            (200, true, None, None),
            (429, false, Some(FailureKind::RateLimited), Some(120_000)),
            (
                503,
                false,
                Some(FailureKind::TemporarilyUnavailable),
                Some(120_000),
            ),
            (404, false, Some(FailureKind::Rejected), Some(120_000)),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = vec![0; 8192];
                let mut read = 0;
                loop {
                    let n = socket.read(&mut bytes[read..]).await.unwrap();
                    assert!(n > 0);
                    read += n;
                    if bytes[..read].windows(4).any(|v| v == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: 100\r\nRetry-After: 120\r\nConnection: close\r\n\r\nx"
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let provider = RealProviders::loopback(&endpoint).unwrap();
            let accepted = now();
            let result = provider
                .request(
                    "FCM",
                    Platform::Android,
                    "synthetic-token",
                    json!({"base_url":"https://fixture.invalid","body":"small"}),
                    "delivery",
                    "device",
                    accepted,
                    accepted + 60_000,
                )
                .await;
            server.await.unwrap();
            assert_eq!(result.status_code, status);
            assert_eq!(result.success, success);
            assert_eq!(result.failure_kind, failure);
            assert_eq!(result.retry_after_millis, retry);
            assert_eq!(provider.transport_errors(), 1);
        }
    }

    #[tokio::test]
    async fn ordinary_provider_severity_keeps_mainline_priority_and_interruption() {
        for (severity, fcm_priority, interruption) in [
            ("critical", "HIGH", "critical"),
            ("high", "HIGH", "time-sensitive"),
            ("normal", "HIGH", "active"),
            ("low", "NORMAL", "passive"),
        ] {
            let (tx, mut rx) = tokio::sync::mpsc::channel(2);
            let app = axum::Router::new().fallback(axum::routing::post(
                move |axum::Json(body): axum::Json<Value>| {
                    let tx = tx.clone();
                    async move {
                        tx.send(body).await.unwrap();
                        axum::Json(json!({}))
                    }
                },
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let provider = RealProviders::loopback(&endpoint).unwrap();
            for (name, platform) in [("FCM", Platform::Android), ("APNS", Platform::Ios)] {
                let accepted = now();
                assert!(provider.request(name, platform, "synthetic-token",
                    json!({"base_url":"https://fixture.invalid","title":"severity","severity":severity}),
                    "delivery", "device", accepted, accepted + 60_000).await.success);
                let wire = rx.recv().await.unwrap();
                if name == "FCM" {
                    assert_eq!(wire["message"]["android"]["priority"], fcm_priority);
                } else {
                    assert_eq!(wire["aps"]["interruption-level"], interruption);
                }
            }
            let wakeup = apns_body(&wakeup_data(&BTreeMap::from([(
                "severity".into(),
                severity.into(),
            )])));
            assert!(wakeup["aps"].get("interruption-level").is_none());
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
    }

    #[test]
    fn provider_delay_floors_and_terminal_token_failure() {
        assert_eq!(
            classify("FCM", 429, b"{}", None).retry_after_millis,
            Some(60_000)
        );
        assert_eq!(
            classify("FCM", 503, b"{}", Some(1000)).retry_after_millis,
            Some(10_000)
        );
        assert_eq!(
            classify("APNS", 503, b"{}", None).retry_after_millis,
            Some(900_000)
        );
        assert!(
            classify("APNS", 403, br#"{"reason":"ExpiredProviderToken"}"#, None).is_retryable()
        );
        assert!(!classify("APNS", 410, br#"{"reason":"Unregistered"}"#, None).is_retryable());
    }
}
