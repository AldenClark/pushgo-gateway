use std::{future::Future, pin::Pin, sync::Arc};

use crate::{Error, storage::Platform};

pub(crate) const PROVIDER_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const PROVIDER_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub(crate) fn local_deadline_expired(deadline: Option<i64>) -> bool {
    deadline.is_some_and(|expires_at| {
        crate::ordinary::expiry::is_expired(expires_at, chrono::Utc::now().timestamp_millis())
    })
}

/// Provider bodies are diagnostics, never message content. An absent or false
/// Content-Length must not turn a single response into unbounded allocation.
/// An incomplete diagnostic is discarded rather than parsed as a token error.
pub(crate) async fn bounded_response_body(mut response: reqwest::Response) -> Vec<u8> {
    const LIMIT: usize = 16 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > LIMIT as u64)
    {
        return Vec::new();
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if chunk.len() <= LIMIT - body.len() => {
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return body,
            Ok(Some(_)) | Err(_) => return Vec::new(),
        }
    }
}

pub mod apns;
pub mod apns_client;
pub mod error;
pub mod fcm;
pub mod fcm_client;
pub mod wns;
pub mod wns_client;

pub use apns_client::ApnsService;
pub(crate) use error::ProviderFailure;
pub use error::ProviderFailureKind;
pub use fcm_client::FcmService;
pub use wns_client::WnsService;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: Arc<str>,
    pub expires_in: u64,
}

#[derive(Debug, Clone)]
pub struct FcmAccess {
    pub token: TokenInfo,
    pub project_id: Arc<str>,
}

#[derive(Debug)]
pub struct DispatchResult {
    pub success: bool,
    pub status_code: u16,
    #[allow(dead_code)]
    pub error: Option<Error>,
    pub failure_kind: Option<ProviderFailureKind>,
    pub retry_after_millis: Option<i64>,
}

impl DispatchResult {
    pub(crate) fn delivery_expired() -> Self {
        Self {
            success: false,
            status_code: 0,
            error: None,
            failure_kind: Some(ProviderFailureKind::DeliveryExpired),
            retry_after_millis: None,
        }
    }
    pub(crate) fn watch_alert_expired() -> Self {
        Self {
            success: false,
            status_code: 0,
            error: None,
            failure_kind: Some(ProviderFailureKind::WatchAlertExpired),
            retry_after_millis: None,
        }
    }

    pub(crate) fn success(status_code: u16) -> Self {
        Self {
            success: true,
            status_code,
            error: None,
            failure_kind: None,
            retry_after_millis: None,
        }
    }

    pub(crate) fn from_error(status_code: u16, error: Error) -> Self {
        Self {
            success: false,
            status_code,
            error: Some(error),
            failure_kind: None,
            retry_after_millis: None,
        }
    }

    pub(crate) fn transport(error: Error) -> Self {
        Self {
            success: false,
            status_code: 0,
            error: Some(error),
            failure_kind: Some(ProviderFailureKind::Transport),
            retry_after_millis: None,
        }
    }

    pub(crate) fn provider_access_failure(error: Error) -> Self {
        Self {
            success: false,
            status_code: 0,
            error: Some(error),
            // Credential/token acquisition can fail because its remote service
            // or local signer is temporarily unavailable. A durable delivery
            // must stay retryable instead of being finalized as a permanent
            // provider failure before any provider request was attempted.
            failure_kind: Some(ProviderFailureKind::TemporarilyUnavailable),
            retry_after_millis: None,
        }
    }

    pub(crate) fn upstream(provider: &'static str, failure: ProviderFailure) -> Self {
        Self {
            success: false,
            status_code: failure.status_code,
            error: Some(Error::Upstream {
                provider,
                status: failure.status_code,
                message: failure.message,
            }),
            failure_kind: Some(failure.kind),
            retry_after_millis: failure.retry_after_millis,
        }
    }

    pub(crate) fn should_refresh_credentials(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::should_refresh_credentials)
    }

    pub(crate) fn is_retryable(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::is_retryable)
    }

    pub(crate) fn is_invalid_token(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::is_invalid_token)
    }

    pub(crate) fn is_payload_too_large(&self) -> bool {
        self.failure_kind
            .is_some_and(ProviderFailureKind::is_payload_too_large)
    }

    pub(crate) fn failure_kind_name(&self) -> &'static str {
        self.failure_kind
            .map(ProviderFailureKind::as_str)
            .unwrap_or("none")
    }
}

pub trait ApnsTokenProvider: Send + Sync {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
    fn refresh_now<'a>(&'a self) -> BoxFuture<'a, Result<Arc<str>, Error>>;
}

pub trait FcmTokenProvider: Send + Sync {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>>;
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<FcmAccess, Error>>;
}

pub trait WnsTokenProvider: Send + Sync {
    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

pub trait ApnsClient: Send + Sync {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        platform: Platform,
        payload: Arc<apns::ApnsPayload>,
        collapse_id: Option<Arc<str>>,
    ) -> BoxFuture<'a, DispatchResult>;

    /// Ordinary local TTL fence. Real transports recheck after credential await
    /// immediately before HTTP send; this default also fences test substitutes.
    fn send_to_device_before<'a>(
        &'a self,
        device_token: &'a str,
        platform: Platform,
        payload: Arc<apns::ApnsPayload>,
        collapse_id: Option<Arc<str>>,
        expires_at: i64,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            if local_deadline_expired(Some(expires_at)) {
                return DispatchResult::delivery_expired();
            }
            self.send_to_device(device_token, platform, payload, collapse_id)
                .await
        })
    }

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

pub trait FcmClient: Send + Sync {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<fcm::FcmPayload>,
        prepared_body: Option<Arc<[u8]>>,
    ) -> BoxFuture<'a, DispatchResult>;

    fn send_to_device_before<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<fcm::FcmPayload>,
        prepared_body: Option<Arc<[u8]>>,
        expires_at: i64,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            if local_deadline_expired(Some(expires_at)) {
                return DispatchResult::delivery_expired();
            }
            self.send_to_device(device_token, payload, prepared_body)
                .await
        })
    }

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

pub trait WnsClient: Send + Sync {
    fn send_to_device<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<wns::WnsPayload>,
    ) -> BoxFuture<'a, DispatchResult>;

    fn send_to_device_before<'a>(
        &'a self,
        device_token: &'a str,
        payload: Arc<wns::WnsPayload>,
        expires_at: i64,
    ) -> BoxFuture<'a, DispatchResult> {
        Box::pin(async move {
            if local_deadline_expired(Some(expires_at)) {
                return DispatchResult::delivery_expired();
            }
            self.send_to_device(device_token, payload).await
        })
    }

    fn token_info<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;

    fn token_info_fresh<'a>(&'a self) -> BoxFuture<'a, Result<TokenInfo, Error>>;
}

#[cfg(test)]
mod tests {
    use super::DispatchResult;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct DelayedCredentials {
        entered: AtomicUsize,
        changed: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }
    impl DelayedCredentials {
        async fn wait(&self) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        async fn all_entered(&self) {
            loop {
                let notified = self.changed.notified();
                if self.entered.load(Ordering::SeqCst) == 3 {
                    return;
                }
                notified.await;
            }
        }
        fn token() -> super::TokenInfo {
            super::TokenInfo {
                token: Arc::from("synthetic-local-only"),
                expires_in: 60,
            }
        }
    }
    impl super::ApnsTokenProvider for DelayedCredentials {
        fn token_info<'a>(
            &'a self,
        ) -> super::BoxFuture<'a, Result<super::TokenInfo, crate::Error>> {
            Box::pin(async move {
                self.wait().await;
                Ok(Self::token())
            })
        }
        fn token_info_fresh<'a>(
            &'a self,
        ) -> super::BoxFuture<'a, Result<super::TokenInfo, crate::Error>> {
            panic!("expired unsent work must not refresh or resend")
        }
        fn refresh_now<'a>(&'a self) -> super::BoxFuture<'a, Result<Arc<str>, crate::Error>> {
            panic!("expired unsent work must not refresh or resend")
        }
    }
    impl super::FcmTokenProvider for DelayedCredentials {
        fn token_info<'a>(
            &'a self,
        ) -> super::BoxFuture<'a, Result<super::FcmAccess, crate::Error>> {
            Box::pin(async move {
                self.wait().await;
                Ok(super::FcmAccess {
                    token: Self::token(),
                    project_id: Arc::from("synthetic-project"),
                })
            })
        }
        fn token_info_fresh<'a>(
            &'a self,
        ) -> super::BoxFuture<'a, Result<super::FcmAccess, crate::Error>> {
            panic!("expired unsent work must not refresh or resend")
        }
    }
    impl super::WnsTokenProvider for DelayedCredentials {
        fn token_info<'a>(
            &'a self,
        ) -> super::BoxFuture<'a, Result<super::TokenInfo, crate::Error>> {
            Box::pin(async move {
                self.wait().await;
                Ok(Self::token())
            })
        }
        fn token_info_fresh<'a>(
            &'a self,
        ) -> super::BoxFuture<'a, Result<super::TokenInfo, crate::Error>> {
            panic!("expired unsent work must not refresh or resend")
        }
    }

    #[test]
    fn provider_access_failure_remains_retryable() {
        let result = DispatchResult::provider_access_failure(crate::Error::Internal(
            "injected token service outage".to_string(),
        ));
        assert!(result.is_retryable());
        assert!(!result.success);
    }

    #[tokio::test]
    async fn provider_diagnostics_are_bounded_without_content_length() {
        for size in [0, 16 * 1024, 16 * 1024 + 1] {
            let response = reqwest::Response::from(
                axum::http::Response::builder()
                    .body(vec![b'x'; size])
                    .unwrap(),
            );
            let body = super::bounded_response_body(response).await;
            assert_eq!(body.len(), if size <= 16 * 1024 { size } else { 0 });
        }
        let response = reqwest::Response::from(
            axum::http::Response::builder()
                .header("content-length", "1000000000")
                .body(Vec::<u8>::new())
                .unwrap(),
        );
        assert!(super::bounded_response_body(response).await.is_empty());
    }

    #[tokio::test]
    async fn ordinary_deadline_is_rechecked_after_all_three_credential_awaits() {
        let credentials = Arc::new(DelayedCredentials {
            entered: AtomicUsize::new(0),
            changed: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        });
        // These adapters must return before executing HTTP. Reserved loopback
        // discard endpoints ensure an accidental send cannot reach a Provider.
        let apns = super::ApnsService::new(credentials.clone(), "http://127.0.0.1:9").unwrap();
        let fcm = super::FcmService::new(credentials.clone(), "http://127.0.0.1:9").unwrap();
        let wns = super::WnsService::new(credentials.clone()).unwrap();
        let data = hashbrown::HashMap::<String, String>::new();
        let apns_payload = Arc::new(super::apns::ApnsPayload::new(
            Some("synthetic".into()),
            None,
            None,
            None,
            "normal".into(),
            None,
            data.clone(),
        ));
        let fcm_payload = Arc::new(super::fcm::FcmPayload::new(data.clone(), "HIGH", None));
        let wns_payload = Arc::new(super::wns::WnsPayload::new(
            data,
            "delivery",
            super::wns::WnsEnvelopeKind::Notification,
            "normal",
            None,
        ));
        let deadline = chrono::Utc::now().timestamp_millis() + 1_000;
        let tasks = [
            tokio::spawn(async move {
                super::ApnsClient::send_to_device_before(
                    &apns,
                    "synthetic",
                    crate::storage::Platform::IOS,
                    apns_payload,
                    None,
                    deadline,
                )
                .await
            }),
            tokio::spawn(async move {
                super::FcmClient::send_to_device_before(
                    &fcm,
                    "synthetic",
                    fcm_payload,
                    None,
                    deadline,
                )
                .await
            }),
            tokio::spawn(async move {
                super::WnsClient::send_to_device_before(
                    &wns,
                    "http://127.0.0.1:9/channel",
                    wns_payload,
                    deadline,
                )
                .await
            }),
        ];
        tokio::time::timeout(
            std::time::Duration::from_millis(900),
            credentials.all_entered(),
        )
        .await
        .expect("all transports must reach credential await while local TTL is live");
        let remaining = deadline.saturating_sub(chrono::Utc::now().timestamp_millis());
        tokio::time::sleep(std::time::Duration::from_millis(
            remaining.max(0) as u64 + 1,
        ))
        .await;
        credentials.release.add_permits(3);
        for task in tasks {
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                result.failure_kind,
                Some(super::ProviderFailureKind::DeliveryExpired)
            );
            assert!(!result.success);
            assert!(!result.is_retryable());
        }
    }
}
