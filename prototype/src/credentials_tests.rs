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

// Both production service traits remain injectable. This owner deliberately
// distinguishes APNs refresh_now from token_info_fresh to catch wrong wiring.
struct ExistingSyntheticOwner {
    calls: Mutex<Vec<&'static str>>,
}
impl pushgo_gateway::providers::FcmTokenProvider for ExistingSyntheticOwner {
    fn token_info<'a>(
        &'a self,
    ) -> pushgo_gateway::providers::BoxFuture<
        'a,
        Result<pushgo_gateway::providers::FcmAccess, pushgo_gateway::Error>,
    > {
        self.calls.lock().unwrap().push("fcm-current");
        Box::pin(async { Ok(existing_fcm_access("synthetic-current")) })
    }
    fn token_info_fresh<'a>(
        &'a self,
    ) -> pushgo_gateway::providers::BoxFuture<
        'a,
        Result<pushgo_gateway::providers::FcmAccess, pushgo_gateway::Error>,
    > {
        self.calls.lock().unwrap().push("fcm-fresh");
        Box::pin(async { Ok(existing_fcm_access("synthetic-fresh")) })
    }
}
fn existing_fcm_access(token: &str) -> pushgo_gateway::providers::FcmAccess {
    pushgo_gateway::providers::FcmAccess {
        project_id: Arc::from("synthetic-existing-project"),
        token: pushgo_gateway::providers::TokenInfo {
            token: Arc::from(token),
            expires_in: 3600,
        },
    }
}
impl pushgo_gateway::providers::ApnsTokenProvider for ExistingSyntheticOwner {
    fn token_info<'a>(
        &'a self,
    ) -> pushgo_gateway::providers::BoxFuture<
        'a,
        Result<pushgo_gateway::providers::TokenInfo, pushgo_gateway::Error>,
    > {
        self.calls.lock().unwrap().push("apns-current");
        Box::pin(async { Ok(existing_fcm_access("synthetic-current").token) })
    }
    fn token_info_fresh<'a>(
        &'a self,
    ) -> pushgo_gateway::providers::BoxFuture<
        'a,
        Result<pushgo_gateway::providers::TokenInfo, pushgo_gateway::Error>,
    > {
        self.calls.lock().unwrap().push("apns-fresh-unexpected");
        Box::pin(async {
            Err(pushgo_gateway::Error::Internal(
                "unexpected refresh seam".into(),
            ))
        })
    }
    fn refresh_now<'a>(
        &'a self,
    ) -> pushgo_gateway::providers::BoxFuture<'a, Result<Arc<str>, pushgo_gateway::Error>> {
        self.calls.lock().unwrap().push("apns-refresh-now");
        Box::pin(async { Ok(Arc::from("synthetic-fresh")) })
    }
}

#[tokio::test]
async fn existing_production_token_provider_traits_keep_refresh_ownership() {
    let owner = Arc::new(ExistingSyntheticOwner {
        calls: Mutex::new(Vec::new()),
    });
    let credentials =
        crate::credentials::ExistingTokenCredentials::new(owner.clone(), owner.clone());
    assert_eq!(
        credentials.fcm(false).await.unwrap().access_token.as_ref(),
        "synthetic-current"
    );
    assert_eq!(
        credentials.fcm(true).await.unwrap().access_token.as_ref(),
        "synthetic-fresh"
    );
    assert_eq!(
        credentials.apns(false).await.unwrap().access_token.as_ref(),
        "synthetic-current"
    );
    assert_eq!(
        credentials.apns(true).await.unwrap().access_token.as_ref(),
        "synthetic-fresh"
    );
    assert_eq!(
        *owner.calls.lock().unwrap(),
        [
            "fcm-current",
            "fcm-fresh",
            "apns-current",
            "apns-refresh-now"
        ]
    );
}

#[tokio::test]
async fn actual_remote_token_service_owner_feeds_bounded_candidate_and_next_attempt() {
    let token_requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let tokens_seen = token_requests.clone();
    let token_app = axum::Router::new().fallback(move |uri: Uri| {
        let requests = tokens_seen.clone();
        async move {
            let mut requests = requests.lock().unwrap();
            requests.push(uri.to_string());
            let generation = requests.len();
            axum::Json(json!({"success":true,"data":{
                "token":format!("synthetic-remote-{generation}"),
                "expires_in":3600,"project_id":"synthetic-remote-project"
            }}))
        }
    });
    let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_endpoint = format!("http://{}", token_listener.local_addr().unwrap());
    let token_server =
        tokio::spawn(async move { axum::serve(token_listener, token_app).await.unwrap() });
    let credentials = Arc::new(
        crate::credentials::ExistingTokenCredentials::loopback_remote(&token_endpoint).unwrap(),
    );
    let requests = Arc::new(Mutex::new(Vec::<(String, HeaderMap, Value)>::new()));
    let captured = requests.clone();
    let provider_app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
        let captured = captured.clone();
        async move {
            let mut captured = captured.lock().unwrap();
            let first = !captured.iter().any(|(path, _, _)| path == uri.path());
            captured.push((uri.path().into(), headers, body));
            if first {
                (StatusCode::UNAUTHORIZED, axum::Json(json!({"reason":"ExpiredProviderToken","error":{"status":"UNAUTHENTICATED"}})))
            } else {
                (StatusCode::OK, axum::Json(json!({})))
            }
        }
    });
    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_endpoint = format!("http://{}", provider_listener.local_addr().unwrap());
    let provider_server =
        tokio::spawn(async move { axum::serve(provider_listener, provider_app).await.unwrap() });
    let transport = RealProviders::loopback_with_credentials(
        &provider_endpoint,
        2,
        credentials.clone(),
        Arc::from("synthetic.topic"),
    )
    .unwrap();
    let accepted = crate::store::now();
    for (index, (provider, platform)) in [("FCM", Platform::Android), ("APNS", Platform::Ios)]
        .into_iter()
        .enumerate()
    {
        let payload = json!({"base_url":"https://fixture.invalid","message_id":"stable-remote-message","body":"synthetic"});
        let first = transport
            .send(
                provider,
                platform,
                "synthetic-device",
                payload.clone(),
                "stable-remote-delivery",
                "stable-remote-device",
                accepted,
                accepted + 60_000,
            )
            .await;
        assert_eq!(first.failure_kind, Some(FailureKind::CredentialsExpired));
        assert_eq!(
            requests.lock().unwrap().len(),
            index * 2 + 1,
            "refresh never resends provider HTTP inline"
        );
        assert_eq!(
            token_requests.lock().unwrap().len(),
            index * 2 + 2,
            "current fetch and explicit refresh use the existing Remote owner"
        );
        let second = transport
            .send(
                provider,
                platform,
                "synthetic-device",
                payload,
                "stable-remote-delivery",
                "stable-remote-device",
                accepted,
                accepted + 60_000,
            )
            .await;
        assert!(second.success);
        assert_eq!(
            token_requests.lock().unwrap().len(),
            index * 2 + 2,
            "next attempt uses owner cache"
        );
        let captured = requests.lock().unwrap();
        for (offset, (_, headers, body)) in captured[index * 2..index * 2 + 2].iter().enumerate() {
            assert_eq!(
                headers["authorization"],
                format!("Bearer synthetic-remote-{}", index * 2 + offset + 1)
            );
            let data = if provider == "FCM" {
                &body["message"]["data"]
            } else {
                body
            };
            assert_eq!(data["delivery_id"], "stable-remote-delivery");
            assert_eq!(data["provider_device_key"], "stable-remote-device");
            assert_eq!(data["message_id"], "stable-remote-message");
            assert_eq!(data["sent_at"], accepted.to_string());
            if provider == "APNS" {
                assert_eq!(
                    headers["apns-expiration"],
                    ((accepted + 60_000) / 1000).to_string()
                );
            }
        }
    }
    assert_eq!(
        *token_requests.lock().unwrap(),
        [
            "/provider/token?provider=fcm",
            "/provider/token?provider=fcm&force_refresh=true",
            "/provider/token/production?provider=apns",
            "/provider/token/production?provider=apns",
        ]
    );
    provider_server.abort();
    token_server.abort();
    assert!(provider_server.await.unwrap_err().is_cancelled());
    assert!(token_server.await.unwrap_err().is_cancelled());
}

#[test]
fn synthetic_remote_constructor_rejects_non_loopback_and_ambiguous_urls() {
    for url in [
        "https://example.invalid",
        "http://localhost:1234",
        "http://127.0.0.1",
        "http://127.0.0.1:1234/path",
        "http://127.0.0.1:1234?query=1",
    ] {
        assert!(matches!(
            crate::credentials::ExistingTokenCredentials::loopback_remote(url),
            Err(CredentialError::Invalid)
        ));
    }
}

#[test]
fn configured_https_provider_origins_validate_without_io_or_token_acquisition() {
    let owner = Arc::new(ExistingSyntheticOwner {
        calls: Mutex::new(Vec::new()),
    });
    let configured = |fcm: &str, apns: &str, budget, topic: &str| {
        RealProviders::configured(
            fcm,
            apns,
            budget,
            owner.clone(),
            owner.clone(),
            Arc::from(topic),
        )
    };
    let transport = configured(
        "https://fcm.synthetic.invalid",
        "https://apns.synthetic.invalid:8443/",
        3,
        "synthetic.topic",
    )
    .unwrap();
    assert_eq!(
        transport.resource_snapshot()["provider_client_owners"],
        json!([false, false])
    );
    assert_eq!(
        transport.resource_snapshot()["idle_connections_per_provider_limit"],
        3
    );
    for endpoint in [
        "http://127.0.0.1:1234",
        "http://fcm.synthetic.invalid",
        "https://fcm.synthetic.invalid/path",
        "https://fcm.synthetic.invalid?query=1",
        "https://fcm.synthetic.invalid#fragment",
        "https://user@fcm.synthetic.invalid",
        "https://fcm.synthetic.invalid:0",
        "invalid",
    ] {
        assert!(
            configured(
                endpoint,
                "https://apns.synthetic.invalid",
                3,
                "synthetic.topic"
            )
            .is_err()
        );
        assert!(
            configured(
                "https://fcm.synthetic.invalid",
                endpoint,
                3,
                "synthetic.topic"
            )
            .is_err()
        );
    }
    assert!(
        configured(
            "https://fcm.synthetic.invalid",
            "https://apns.synthetic.invalid",
            0,
            "synthetic.topic"
        )
        .is_err()
    );
    assert!(
        configured(
            "https://fcm.synthetic.invalid",
            "https://apns.synthetic.invalid",
            3,
            "invalid/topic"
        )
        .is_err()
    );
    assert!(owner.calls.lock().unwrap().is_empty());
    assert!(RealProviders::loopback("https://127.0.0.1:1234").is_err());
    assert!(RealProviders::loopback("http://provider.synthetic.invalid:1234").is_err());
}
