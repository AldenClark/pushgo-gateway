use super::store::{AcceptRequest, DeliveryStore, KernelError};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;

type Stats = Arc<dyn Fn() -> Value + Send + Sync>;
#[derive(Clone)]
struct HttpState {
    store: DeliveryStore,
    stats: Stats,
}
#[derive(Clone)]
struct Admission {
    ingress: Arc<Semaphore>,
    control: Arc<Semaphore>,
    auth_hash: Option<[u8; 32]>,
    password_window: Arc<Mutex<PasswordWindow>>,
}
pub fn router(store: DeliveryStore, stats: Stats) -> Router {
    router_with_auth(store, stats, None)
}
/// Same shared-token/public-password policy as the ordinary Gateway router.
/// The supplied token is hashed immediately and never retained in diagnostics.
pub fn router_with_auth(store: DeliveryStore, stats: Stats, shared_token: Option<&str>) -> Router {
    let total = store.config.max_handlers;
    let reserve = (total / 8).max(1).min(total);
    let admission = if total == 1 {
        let single = Arc::new(Semaphore::new(1));
        Admission {
            ingress: single.clone(),
            control: single,
            auth_hash: shared_token.map(|v| *blake3::hash(v.as_bytes()).as_bytes()),
            password_window: Arc::default(),
        }
    } else {
        Admission {
            ingress: Arc::new(Semaphore::new(total - reserve)),
            control: Arc::new(Semaphore::new(reserve)),
            auth_hash: shared_token.map(|v| *blake3::hash(v.as_bytes()).as_bytes()),
            password_window: Arc::default(),
        }
    };
    let limit = store.config.max_body_bytes;
    let app = Router::new()
        .route("/device/register", post(register))
        .route("/channel/device", post(route))
        .route("/channel/subscribe", post(subscribe))
        .route("/message", post(message))
        .route("/send_status/{op_id}", get(send_status))
        .route("/messages/pull", post(pull_legacy))
        .route("/messages/ack", post(ack_legacy))
        .route("/v2/messages/pull", post(pull))
        .route("/v2/messages/ack", post(ack))
        .route("/__fixture/stats", get(statistics))
        .route("/__fixture/status", post(status))
        .fallback(route_not_found)
        .layer(DefaultBodyLimit::max(limit))
        .layer(middleware::from_fn_with_state(admission, bound_handlers))
        .with_state(HttpState {
            store: store.clone(),
            stats,
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
async fn bound_handlers(
    State(state): State<Admission>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
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
    } else if ingress || path.ends_with("/channel/subscribe") {
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
    let permit = if ingress {
        state.ingress.clone()
    } else {
        state.control.clone()
    }
    .try_acquire_owned();
    match permit {
        Ok(_permit) => next.run(request).await,
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"code":"handler_capacity"})),
        )
            .into_response(),
    }
}
impl IntoResponse for KernelError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
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
                json!({"success":false,"code":status.as_u16(),"error_code":code,"message":message}),
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
}
async fn register(
    State(state): State<HttpState>,
    Json(input): Json<Register>,
) -> Result<Json<Value>, KernelError> {
    let key = state.store.register(&input.platform).await?;
    Ok(ok(json!({"device_key":key,"issued_new_key":true})))
}
#[derive(Deserialize)]
struct Route {
    device_key: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(alias = "provider")]
    channel_type: String,
    #[serde(alias = "token")]
    provider_token: String,
}
async fn route(
    State(state): State<HttpState>,
    Json(input): Json<Route>,
) -> Result<Json<Value>, KernelError> {
    state
        .store
        .route(
            &input.device_key,
            input.platform.as_deref(),
            &input.channel_type,
            &input.provider_token,
        )
        .await?;
    Ok(ok(
        json!({"device_key":input.device_key,"channel_type":input.channel_type}),
    ))
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
