use crate::{
    ProviderTransport, RealProviders,
    credentials::{ApnsCredential, CredentialError, CredentialProvider, FcmCredential},
    transport::{BoxFuture, FailureKind},
    types::Platform,
};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct SyntheticCredentials {
    version: AtomicUsize,
    calls: Mutex<Vec<(&'static str, bool)>>,
    unavailable: bool,
    refresh_unavailable: bool,
}
impl SyntheticCredentials {
    fn new(unavailable: bool, refresh_unavailable: bool) -> Self {
        Self {
            version: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            unavailable,
            refresh_unavailable,
        }
    }
    fn acquire(&self, provider: &'static str, refresh: bool) -> Result<String, CredentialError> {
        self.calls.lock().unwrap().push((provider, refresh));
        if self.unavailable || (refresh && self.refresh_unavailable) {
            return Err(CredentialError::Unavailable);
        }
        if refresh {
            self.version.fetch_add(1, Ordering::SeqCst);
        }
        Ok(format!(
            "synthetic-{provider}-{}",
            self.version.load(Ordering::SeqCst)
        ))
    }
}
impl CredentialProvider for SyntheticCredentials {
    fn fcm<'a>(&'a self, refresh: bool) -> BoxFuture<'a, Result<FcmCredential, CredentialError>> {
        Box::pin(
            async move { FcmCredential::new("synthetic-project", &self.acquire("FCM", refresh)?) },
        )
    }
    fn apns<'a>(&'a self, refresh: bool) -> BoxFuture<'a, Result<ApnsCredential, CredentialError>> {
        Box::pin(async move { ApnsCredential::new(&self.acquire("APNS", refresh)?) })
    }
}

#[tokio::test]
async fn expired_credentials_refresh_without_inline_resend_and_preserve_retry_identity() {
    for (provider, platform, status, error_body) in [
        (
            "FCM",
            Platform::Android,
            401,
            json!({"error":{"status":"UNAUTHENTICATED"}}),
        ),
        (
            "FCM",
            Platform::Android,
            403,
            json!({"error":{"status":"PERMISSION_DENIED"}}),
        ),
        (
            "APNS",
            Platform::Ios,
            401,
            json!({"reason":"ExpiredProviderToken"}),
        ),
        (
            "APNS",
            Platform::Macos,
            403,
            json!({"reason":"ExpiredProviderToken"}),
        ),
    ] {
        let captured = Arc::new(Mutex::new(Vec::<(String, HeaderMap, Value)>::new()));
        let handler_capture = captured.clone();
        let app = axum::Router::new().fallback(axum::routing::post(
            move |uri: Uri, headers: HeaderMap, body: Bytes| {
                let captured = handler_capture.clone();
                let error_body = error_body.clone();
                async move {
                    let first = {
                        let mut captured = captured.lock().unwrap();
                        captured.push((
                            uri.to_string(),
                            headers,
                            serde_json::from_slice(&body).unwrap(),
                        ));
                        captured.len() == 1
                    };
                    if first {
                        (
                            StatusCode::from_u16(status).unwrap(),
                            axum::Json(error_body),
                        )
                            .into_response()
                    } else {
                        (StatusCode::OK, axum::Json(json!({}))).into_response()
                    }
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let credentials = Arc::new(SyntheticCredentials::new(false, false));
        let transport = RealProviders::loopback_with_credentials(
            &endpoint,
            2,
            credentials.clone(),
            Arc::from("synthetic.topic"),
        )
        .unwrap();
        let accepted = crate::store::now();
        let payload = json!({"base_url":"https://fixture.invalid","body":"synthetic","message_id":"stable-message"});
        let first = transport
            .send(
                provider,
                platform,
                "synthetic-device",
                payload.clone(),
                "stable-delivery",
                "stable-device",
                accepted,
                accepted + 60_000,
            )
            .await;
        assert_eq!(first.status_code, status);
        assert_eq!(first.failure_kind, Some(FailureKind::CredentialsExpired));
        assert!(first.is_retryable());
        assert_eq!(
            captured.lock().unwrap().len(),
            1,
            "refresh must not resend inline"
        );
        assert_eq!(
            *credentials.calls.lock().unwrap(),
            vec![(provider, false), (provider, true)]
        );
        let second = transport
            .send(
                provider,
                platform,
                "synthetic-device",
                payload,
                "stable-delivery",
                "stable-device",
                accepted,
                accepted + 60_000,
            )
            .await;
        assert!(second.success);
        {
            let captured = captured.lock().unwrap();
            assert_eq!(captured.len(), 2);
            let expected_target = if provider == "FCM" {
                "/v1/projects/synthetic-project/messages:send"
            } else {
                "/3/device/synthetic-device"
            };
            for (index, (target, headers, body)) in captured.iter().enumerate() {
                assert_eq!(target, expected_target);
                assert_eq!(
                    headers["authorization"],
                    format!("Bearer synthetic-{provider}-{index}")
                );
                let data = if provider == "FCM" {
                    &body["message"]["data"]
                } else {
                    body
                };
                assert_eq!(data["delivery_id"], "stable-delivery");
                assert_eq!(data["provider_device_key"], "stable-device");
                assert_eq!(data["message_id"], "stable-message");
                assert_eq!(data["sent_at"], accepted.to_string());
                if provider == "APNS" {
                    assert_eq!(headers["apns-topic"], "synthetic.topic");
                }
            }
        }
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
async fn credential_acquisition_failure_is_retryable_without_provider_http() {
    let requests = Arc::new(AtomicUsize::new(0));
    let handler_requests = requests.clone();
    let app = axum::Router::new().fallback(move || {
        handler_requests.fetch_add(1, Ordering::SeqCst);
        async { axum::Json(json!({})) }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let credentials = Arc::new(SyntheticCredentials::new(true, false));
    let transport = RealProviders::loopback_with_credentials(
        &endpoint,
        2,
        credentials.clone(),
        Arc::from("synthetic.topic"),
    )
    .unwrap();
    for (provider, platform) in [("FCM", Platform::Android), ("APNS", Platform::Ios)] {
        let accepted = crate::store::now();
        let result = transport
            .send(
                provider,
                platform,
                "synthetic-device",
                json!({"base_url":"https://fixture.invalid"}),
                "delivery",
                "device",
                accepted,
                accepted + 60_000,
            )
            .await;
        assert_eq!(result.status_code, 0);
        assert_eq!(result.failure_kind_name(), "provider_access_failed");
        assert!(result.is_retryable());
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        *credentials.calls.lock().unwrap(),
        vec![("FCM", false), ("APNS", false)]
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn unauthorized_apns_does_not_refresh_and_failed_refresh_preserves_original_dispatch() {
    for (provider, platform, body, refresh, kind) in [
        (
            "APNS",
            Platform::Ios,
            json!({"reason":"InvalidProviderToken"}),
            false,
            FailureKind::Unauthorized,
        ),
        (
            "APNS",
            Platform::Ios,
            json!({"reason":"ExpiredProviderToken"}),
            true,
            FailureKind::CredentialsExpired,
        ),
        (
            "FCM",
            Platform::Android,
            json!({"error":{"status":"PERMISSION_DENIED"}}),
            true,
            FailureKind::CredentialsExpired,
        ),
        (
            "FCM",
            Platform::Android,
            json!({"error":{"details":[{"errorCode":"UNREGISTERED"}]}}),
            false,
            FailureKind::InvalidToken,
        ),
    ] {
        let requests = Arc::new(AtomicUsize::new(0));
        let handler_requests = requests.clone();
        let app = axum::Router::new().fallback(move || {
            handler_requests.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            async move { (StatusCode::FORBIDDEN, axum::Json(body)) }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let credentials = Arc::new(SyntheticCredentials::new(false, true));
        let transport = RealProviders::loopback_with_credentials(
            &endpoint,
            2,
            credentials.clone(),
            Arc::from("synthetic.topic"),
        )
        .unwrap();
        let accepted = crate::store::now();
        let result = transport
            .send(
                provider,
                platform,
                "synthetic-device",
                json!({"base_url":"https://fixture.invalid"}),
                "delivery",
                "device",
                accepted,
                accepted + 60_000,
            )
            .await;
        assert_eq!(result.status_code, 403);
        assert_eq!(result.failure_kind, Some(kind));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let expected = if refresh {
            vec![(provider, false), (provider, true)]
        } else {
            vec![(provider, false)]
        };
        assert_eq!(*credentials.calls.lock().unwrap(), expected);
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}
