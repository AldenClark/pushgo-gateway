use super::store::{AcceptRequest, KernelError, MESSAGE_SUBMISSION_BODY_BYTES};
use crate::{ordinary_store::OrdinaryStore, private_http::PrivateHttp};
use axum::{
    Json, Router,
    body::{Body, HttpBody},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{StreamExt, stream};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

type Stats = Arc<dyn Fn() -> Value + Send + Sync>;
#[derive(Clone)]
struct HttpState {
    store: OrdinaryStore,
    stats: Stats,
    private: Option<PrivateHttp>,
}
#[derive(Clone)]
struct Admission {
    requests: Arc<Semaphore>,
    control: Arc<Semaphore>,
    auth_hash: Option<[u8; 32]>,
    password_window: Arc<Mutex<PasswordWindow>>,
    health: Arc<crate::store::Health>,
}
pub fn router(store: impl Into<OrdinaryStore>, stats: Stats) -> Router {
    router_with_auth(store, stats, None)
}
/// Same shared-token/public-password policy as the ordinary Gateway router.
/// The supplied token is hashed immediately and never retained in diagnostics.
pub fn router_with_auth(
    store: impl Into<OrdinaryStore>,
    stats: Stats,
    shared_token: Option<&str>,
) -> Router {
    router_with_private(store, stats, shared_token, None)
}
/// Full ordinary HTTP router with optional joined Private discovery/upgrade owner.
pub fn router_with_private(
    store: impl Into<OrdinaryStore>,
    stats: Stats,
    shared_token: Option<&str>,
    private: Option<PrivateHttp>,
) -> Router {
    let store = store.into();
    let total = store.config.max_handlers;
    let reserve = (total / 8).max(1).min(total);
    let admission = Admission {
        requests: Arc::new(Semaphore::new(total)),
        control: Arc::new(Semaphore::new(reserve)),
        auth_hash: shared_token.map(|v| *blake3::hash(v.as_bytes()).as_bytes()),
        password_window: Arc::default(),
        health: store.health.clone(),
    };
    let limit = store.config.max_body_bytes;
    let mut app = Router::new()
        .route("/gateway/profile", get(gateway_profile))
        .route("/device/register", post(register))
        .route("/channel/device", post(route))
        .route("/channel/subscribe", post(subscribe))
        .route("/channel/unsubscribe", post(unsubscribe))
        .route("/channel/sync", post(sync_channels))
        .route("/channel/rename", post(rename_channel))
        .route("/channel/exists", get(channel_exists))
        .route("/channel/device/delete", post(delete_route))
        .route("/channel/device/provider-token/retire", post(retire_token))
        .route(
            "/message",
            post(message).layer(DefaultBodyLimit::max(MESSAGE_SUBMISSION_BODY_BYTES)),
        )
        .route("/send_status/{op_id}", get(send_status))
        .route("/messages/pull", post(pull_legacy))
        .route("/messages/ack", post(ack_legacy))
        .route("/v2/messages/pull", post(pull))
        .route("/v2/messages/ack", post(ack))
        .route("/__fixture/stats", get(statistics))
        .route("/__fixture/status", post(status));
    if private.as_ref().is_some_and(PrivateHttp::wss_enabled) {
        app = app.route("/private/ws", get(private_ws));
    }
    let app = app
        .fallback(route_not_found)
        .layer(DefaultBodyLimit::max(limit))
        .layer(middleware::from_fn_with_state(admission, bound_handlers))
        .with_state(HttpState {
            store: store.clone(),
            stats,
            private,
        });
    if store.config.public_base_url.is_empty() {
        return app;
    }
    let url =
        reqwest::Url::parse(&store.config.public_base_url).expect("validated public_base_url");
    let prefix = url.path().trim_end_matches('/');
    if prefix.is_empty() {
        app
    } else {
        Router::new().nest(prefix, app).fallback(route_not_found)
    }
}
async fn gateway_profile(State(state): State<HttpState>) -> Json<Value> {
    let data = state
        .private
        .as_ref()
        .map(PrivateHttp::profile)
        .unwrap_or_else(crate::private_http::disabled_profile);
    Json(json!({"success":true,"data":data}))
}
async fn private_ws(
    ws: axum::extract::ws::WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    State(state): State<HttpState>,
) -> Response {
    match state.private {
        Some(private) => private.upgrade(ws, &headers),
        None => KernelError::Unavailable.into_response(),
    }
}
async fn bound_handlers(
    State(state): State<Admission>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if let Err(error) = state.health.ensure() {
        return error.into_response();
    }
    let path = request.uri().path();
    let ingress = path.ends_with("/message");
    if let Some(expected) = state.auth_hash {
        let valid = request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|raw| {
                let mut fields = raw.split_whitespace();
                let scheme = fields.next().unwrap_or("");
                let token = fields.next().unwrap_or("");
                if !scheme.eq_ignore_ascii_case("bearer")
                    || token.is_empty()
                    || token.len() > 4096
                    || fields.next().is_some()
                {
                    return false;
                }
                let actual = blake3::hash(token.as_bytes());
                expected
                    .iter()
                    .zip(actual.as_bytes())
                    .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
                    == 0
            });
        if !valid {
            return KernelError::Unauthorized.into_response();
        }
    } else if ingress
        || path.ends_with("/channel/subscribe")
        || path.ends_with("/channel/sync")
        || path.ends_with("/channel/rename")
    {
        let ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|v| v.0.ip());
        let minute = chrono::Utc::now().timestamp().max(0) as u64 / 60;
        let allowed = state
            .password_window
            .lock()
            .is_ok_and(|mut window| window.allow(ip, minute));
        if !allowed {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"success":false,"code":429,"error_code":"rate_limited","message":"rate limited"}))).into_response();
        }
    }
    let request_permit = match state.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"code":"handler_capacity"})),
            )
                .into_response();
        }
    };
    // Wait before handler JSON extraction while already owning a request slot:
    // at most max_handlers requests can wait, with no parsed response payload.
    // Separate semaphores also avoid double-acquiring a shared slot at total=1.
    let control_permit = if ingress {
        None
    } else {
        match state.control.clone().acquire_owned().await {
            Ok(permit) => Some(permit),
            Err(_) => return KernelError::Capacity.into_response(),
        }
    };
    retain_response_permit(
        next.run(request).await,
        ResponsePermits {
            _request: request_permit,
            _control: control_permit,
        },
    )
}
struct ResponsePermits {
    _request: OwnedSemaphorePermit,
    _control: Option<OwnedSemaphorePermit>,
}
// Existing routes return JSON or empty bodies. This data-stream adapter owns
// their admission slot through response EOF/drop; it is not a proxy/trailer
// adapter. Preserve known wire lengths when replacing Body's exact size hint.
fn retain_response_permit(response: Response, permit: ResponsePermits) -> Response {
    let (mut parts, body) = response.into_parts();
    if body.is_end_stream() {
        drop(permit);
        return Response::from_parts(parts, body);
    }
    if !parts
        .headers
        .contains_key(axum::http::header::CONTENT_LENGTH)
        && let Some(length) = body.size_hint().exact()
    {
        parts
            .headers
            .insert(axum::http::header::CONTENT_LENGTH, length.into());
    }
    let stream = stream::try_unfold(
        (body.into_data_stream(), permit),
        |(mut body, permit)| async move {
            match body.next().await {
                Some(Ok(data)) => Ok(Some((data, (body, permit)))),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            }
        },
    );
    Response::from_parts(parts, Body::from_stream(stream))
}

#[cfg(test)]
#[path = "http_budget_tests.rs"]
mod budget_tests;

impl IntoResponse for KernelError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::Control {
                status,
                code,
                message,
            } => (
                StatusCode::from_u16(*status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                *code,
                message.as_str(),
            ),
            Self::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                message.as_str(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "op_id_payload_conflict",
                "operation fingerprint conflict",
            ),
            Self::ScopeConflict => (
                StatusCode::CONFLICT,
                "op_id_scope_conflict",
                "operation scope conflict",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "send_status_not_found",
                "send status not found",
            ),
            Self::Capacity => (
                StatusCode::SERVICE_UNAVAILABLE,
                "dispatch_capacity_exceeded",
                "authority capacity exceeded",
            ),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "unauthorized"),
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "internal_error",
                "temporarily unavailable",
            ),
        };
        (
            status,
            Json(
                json!({"success":false,"code":status.as_u16(),"error_code":code,"error":message,"message":message,"problem":{"code":code,"category":if status==StatusCode::FORBIDDEN || status==StatusCode::CONFLICT {"conflict"} else if status==StatusCode::NOT_FOUND {"not_found"} else if status==StatusCode::UNAUTHORIZED {"authentication"} else if status.is_server_error() {"internal"} else {"validation"},"status":status.as_u16(),"detail":message,"retryable":status.is_server_error()}}),
            ),
        )
            .into_response()
    }
}
fn ok(data: Value) -> Json<Value> {
    Json(json!({"success":true,"code":0,"data":data}))
}
#[derive(Deserialize)]
struct Register {
    platform: String,
    #[serde(default)]
    device_key: Option<String>,
}
async fn register(
    State(state): State<HttpState>,
    Json(input): Json<Register>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .register_device(&input.platform, input.device_key.as_deref())
        .await?))
}
#[derive(Deserialize)]
struct Route {
    device_key: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(alias = "provider")]
    channel_type: String,
    #[serde(alias = "token")]
    #[serde(default)]
    provider_token: Option<String>,
}
async fn route(
    State(state): State<HttpState>,
    Json(input): Json<Route>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .update_route(
            &input.device_key,
            input.platform.as_deref(),
            &input.channel_type,
            input.provider_token.as_deref(),
        )
        .await?))
}
#[derive(Deserialize)]
struct Subscribe {
    device_key: String,
    #[serde(default)]
    channel_id: Option<String>,
    #[serde(default)]
    channel_name: Option<String>,
    password: String,
}
async fn subscribe(
    State(state): State<HttpState>,
    Json(input): Json<Subscribe>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .subscribe(
            &input.device_key,
            input.channel_id.as_deref(),
            input.channel_name.as_deref(),
            &input.password,
        )
        .await?))
}
#[derive(Deserialize)]
struct Unsubscribe {
    device_key: String,
    channel_id: String,
}
async fn unsubscribe(
    State(state): State<HttpState>,
    Json(input): Json<Unsubscribe>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .unsubscribe(&input.device_key, &input.channel_id)
        .await?))
}
#[derive(Deserialize)]
struct SyncItem {
    channel_id: String,
    password: String,
}
#[derive(Deserialize)]
struct SyncRequest {
    device_key: String,
    channels: Vec<SyncItem>,
}
async fn sync_channels(
    State(state): State<HttpState>,
    Json(input): Json<SyncRequest>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .sync_channels(
            &input.device_key,
            input
                .channels
                .into_iter()
                .map(|item| (item.channel_id, item.password))
                .collect(),
        )
        .await?))
}
#[derive(Deserialize)]
struct Rename {
    channel_id: String,
    channel_name: String,
    password: String,
}
async fn rename_channel(
    State(state): State<HttpState>,
    Json(input): Json<Rename>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .rename_channel(&input.channel_id, &input.channel_name, &input.password)
        .await?))
}
#[derive(Deserialize)]
struct ChannelQuery {
    channel_id: String,
}
async fn channel_exists(
    State(state): State<HttpState>,
    Query(input): Query<ChannelQuery>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state.store.channel_info(&input.channel_id).await?))
}
#[derive(Deserialize)]
struct DeleteRoute {
    device_key: String,
    channel_type: String,
}
async fn delete_route(
    State(state): State<HttpState>,
    Json(input): Json<DeleteRoute>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state
        .store
        .delete_route(&input.device_key, &input.channel_type)
        .await?))
}
#[derive(Deserialize)]
struct RetireToken {
    platform: String,
    provider_token: String,
}
async fn retire_token(
    State(state): State<HttpState>,
    Json(input): Json<RetireToken>,
) -> Result<Json<Value>, KernelError> {
    state
        .store
        .retire_provider_token(&input.platform, &input.provider_token)
        .await?;
    Ok(ok(json!({"retired":true})))
}
async fn message(
    State(state): State<HttpState>,
    Json(input): Json<AcceptRequest>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(serde_json::to_value(state.store.accept(input).await?)?))
}
#[derive(Deserialize)]
struct Pull {
    device_key: String,
    #[serde(default)]
    delivery_id: Option<String>,
}
async fn pull(
    State(state): State<HttpState>,
    Json(input): Json<Pull>,
) -> Result<Json<Value>, KernelError> {
    let (device, delivery) = validate_pull(input)?;
    Ok(ok(state.store.pull(&device, delivery.as_deref()).await?))
}
#[derive(Deserialize)]
struct Ack {
    device_key: String,
    delivery_ids: Vec<String>,
}
async fn ack(
    State(state): State<HttpState>,
    Json(input): Json<Ack>,
) -> Result<Json<Value>, KernelError> {
    let device = validate_device(&input.device_key)?;
    let mut ids = input
        .delivery_ids
        .into_iter()
        .map(|id| validate_delivery(&id))
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() || ids.len() > 200 {
        return Err(KernelError::Invalid(
            "1..200 unique ACK ids required".into(),
        ));
    }
    let requested = ids.len();
    let removed = state.store.ack(&device, ids).await?;
    Ok(ok(
        json!({"requested_count":requested,"removed_count":removed}),
    ))
}
async fn statistics(State(state): State<HttpState>) -> Json<Value> {
    Json((state.stats)())
}
#[derive(Deserialize)]
struct Status {
    op_id: String,
}
async fn status(
    State(state): State<HttpState>,
    Json(input): Json<Status>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state.store.target_status(&input.op_id).await?))
}
async fn send_status(
    State(state): State<HttpState>,
    Path(op_id): Path<String>,
) -> Result<Json<Value>, KernelError> {
    Ok(ok(state.store.status(&op_id).await?))
}

// These route checks preserve the existing ordinary client protocol. They are
// not shared bearer authentication or a replacement for channel password gates.
fn validate_device(raw: &str) -> Result<String, KernelError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(KernelError::Invalid("device_key".into()));
    }
    Ok(value.into())
}
fn validate_delivery(raw: &str) -> Result<String, KernelError> {
    let value = raw.trim();
    if value.is_empty() || value.len() > 128 {
        return Err(KernelError::Invalid("delivery_id".into()));
    }
    Ok(value.into())
}
fn validate_pull(input: Pull) -> Result<(String, Option<String>), KernelError> {
    Ok((
        validate_device(&input.device_key)?,
        input
            .delivery_id
            .as_deref()
            .map(validate_delivery)
            .transpose()?,
    ))
}
async fn pull_legacy(
    State(state): State<HttpState>,
    Json(input): Json<Pull>,
) -> Result<Json<Value>, KernelError> {
    let (device, delivery) = validate_pull(input)?;
    Ok(ok(state
        .store
        .pull_legacy(&device, delivery.as_deref())
        .await?))
}
#[derive(Deserialize)]
struct LegacyAck {
    device_key: String,
    delivery_id: String,
}

#[derive(Default)]
struct PasswordWindow {
    minute: u64,
    global: u32,
    per_ip: HashMap<IpAddr, u32>,
}
impl PasswordWindow {
    fn allow(&mut self, ip: Option<IpAddr>, minute: u64) -> bool {
        if self.minute != minute {
            *self = Self {
                minute,
                ..Self::default()
            };
        }
        if self.global >= 1200
            || ip.is_some_and(|ip| self.per_ip.get(&ip).copied().unwrap_or(0) >= 60)
        {
            return false;
        }
        self.global += 1;
        if let Some(ip) = ip {
            *self.per_ip.entry(ip).or_default() += 1;
        }
        true
    }
}
async fn ack_legacy(
    State(state): State<HttpState>,
    Json(input): Json<LegacyAck>,
) -> Result<Json<Value>, KernelError> {
    let device = validate_device(&input.device_key)?;
    let delivery = validate_delivery(&input.delivery_id)?;
    let removed = state.store.ack(&device, vec![delivery]).await? > 0;
    Ok(ok(json!({"removed":removed})))
}
async fn route_not_found() -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(
            json!({"success":false,"code":404,"error_code":"route_not_found","message":"route_not_found"}),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeliveryStore;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn shared_auth_precedes_json_and_bypasses_public_password_budget_with_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::Config {
            public_base_url: "http://127.0.0.1:65535/gateway".into(),
            ..Default::default()
        };
        let (store, owner) = DeliveryStore::open(
            &format!("sqlite://{}/auth.sqlite", dir.path().display()),
            config,
        )
        .await
        .unwrap();
        let credential = crate::types::generate_hex_id_128();
        let app = router_with_auth(
            store.clone(),
            Arc::new(|| json!({"ok":true})),
            Some(&credential),
        );
        for header in [None, Some("Basic invalid"), Some("Bearer invalid extra")] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/gateway/message")
                .header("content-type", "application/json");
            if let Some(header) = header {
                request = request.header("Authorization", header);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from("invalid json")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        for _ in 0..65 {
            let request = Request::builder()
                .method("POST")
                .uri("/gateway/message")
                .header("Authorization", format!("bEaReR {credential}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let public = router(store.clone(), Arc::new(|| json!({})));
        for n in 0..61 {
            let request = Request::builder()
                .method("POST")
                .uri("/gateway/message")
                .extension(ConnectInfo(
                    "127.0.0.1:43210".parse::<SocketAddr>().unwrap(),
                ))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let response = public.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status() == StatusCode::TOO_MANY_REQUESTS, n == 60);
        }
        store.pool.close().await;
        owner.release();
    }

    async fn sized_json_response(
        app: &Router,
        path: &str,
        input: &Value,
        bytes: usize,
    ) -> Response {
        let mut body = serde_json::to_vec(input).unwrap();
        assert!(body.len() <= bytes);
        body.resize(bytes, b' ');
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn message_body_limit_is_49152_without_expanding_control_routes() {
        assert_eq!(MESSAGE_SUBMISSION_BODY_BYTES, 49152);
        assert_eq!(crate::Config::default().max_body_bytes, 32768);
        for (prefix, control_limit) in [("", 32768), ("/gateway", 32768), ("/custom", 1024)] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = crate::Config {
                public_base_url: format!("http://127.0.0.1:65535{prefix}"),
                max_body_bytes: control_limit,
                ..Default::default()
            };
            config.private.enabled = true;
            let (store, owner) = DeliveryStore::open(
                &format!("sqlite://{}/body-limits.sqlite", dir.path().display()),
                config,
            )
            .await
            .unwrap();
            let device = store.register("android").await.unwrap();
            let password = crate::types::generate_hex_id_128();
            let channel = store
                .subscribe(&device, None, Some("body limit"), &password)
                .await
                .unwrap()["channel_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let app = router(store.clone(), Arc::new(|| json!({})));
            for bytes in [32769, MESSAGE_SUBMISSION_BODY_BYTES] {
                let input = json!({"channel_id":channel,"password":password,"op_id":format!("limit-{bytes}"),"title":"limit","body":"retained"});
                let response =
                    sized_json_response(&app, &format!("{prefix}/message"), &input, bytes).await;
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "message {prefix} at {bytes}"
                );
            }
            let response = sized_json_response(
                &app,
                &format!("{prefix}/message"),
                &json!({}),
                MESSAGE_SUBMISSION_BODY_BYTES + 1,
            )
            .await;
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            for path in [
                "/device/register",
                "/channel/device",
                "/channel/subscribe",
                "/channel/unsubscribe",
                "/channel/sync",
                "/channel/rename",
                "/channel/device/delete",
                "/channel/device/provider-token/retire",
                "/messages/pull",
                "/messages/ack",
                "/v2/messages/pull",
                "/v2/messages/ack",
                "/__fixture/status",
            ] {
                // Missing required fields distinguish accepted body extraction
                // (422) from an over-limit body (413), without mutating control state.
                for (bytes, expected) in [
                    (control_limit, StatusCode::UNPROCESSABLE_ENTITY),
                    (control_limit + 1, StatusCode::PAYLOAD_TOO_LARGE),
                    (MESSAGE_SUBMISSION_BODY_BYTES, StatusCode::PAYLOAD_TOO_LARGE),
                ] {
                    let response =
                        sized_json_response(&app, &format!("{prefix}{path}"), &json!({}), bytes)
                            .await;
                    assert_eq!(
                        response.status(),
                        expected,
                        "control {prefix}{path} at {bytes}"
                    );
                }
            }
            store.pool.close().await;
            owner.release();
        }
    }

    #[test]
    fn password_rate_window_is_bounded_by_inherited_global_budget_and_reclaims_each_minute() {
        let mut window = PasswordWindow::default();
        for n in 0..1200 {
            assert!(window.allow(Some(IpAddr::V6(std::net::Ipv6Addr::from(n as u128 + 1))), 1));
        }
        assert!(!window.allow(None, 1));
        assert_eq!(window.per_ip.len(), 1200);
        assert!(window.allow(None, 2));
        assert!(window.per_ip.is_empty());
    }
}

#[cfg(test)]
#[path = "private_http_tests.rs"]
mod private_tests;
