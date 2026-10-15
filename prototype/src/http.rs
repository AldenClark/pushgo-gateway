use super::store::{AcceptRequest, DeliveryStore, KernelError};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
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
}
pub fn router(store: DeliveryStore, stats: Stats) -> Router {
    let total = store.config.max_handlers;
    let reserve = (total / 8).max(1).min(total);
    let admission = if total == 1 {
        let single = Arc::new(Semaphore::new(1));
        Admission {
            ingress: single.clone(),
            control: single,
        }
    } else {
        Admission {
            ingress: Arc::new(Semaphore::new(total - reserve)),
            control: Arc::new(Semaphore::new(reserve)),
        }
    };
    let limit = store.config.max_body_bytes;
    let app = Router::new()
        .route("/device/register", post(register))
        .route("/channel/device", post(route))
        .route("/channel/subscribe", post(subscribe))
        .route("/message", post(message))
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
    let ingress = request.uri().path() == "/message";
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
        let status = match self {
            Self::Invalid(_) => StatusCode::BAD_REQUEST,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(json!({"success":false,"code":status.as_u16(),"message":self.to_string()})),
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    Ok(ok(state.store.status(&input.op_id).await?))
}

// These route checks preserve the existing ordinary client protocol. They are
// not shared bearer authentication or a replacement for channel password gates.
fn validate_device(raw: &str) -> Result<String, KernelError> {
    let value = raw.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(KernelError::Invalid("device_key".into()));
    }
    Ok(value.into())
}
fn validate_delivery(raw: &str) -> Result<String, KernelError> {
    let value = raw.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
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
#[serde(deny_unknown_fields)]
struct LegacyAck {
    device_key: String,
    delivery_id: String,
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
