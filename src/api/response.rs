use std::borrow::Cow;

use axum::{
    extract::rejection::JsonRejection,
    http::{
        HeaderName, HeaderValue, StatusCode,
        header::{ACCEPT_LANGUAGE, CONTENT_LANGUAGE},
    },
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use tokio::task_local;

use crate::storage::StoreError;
use crate::value::ValueError;

pub(crate) fn ok<T: Serialize>(data: T) -> Response {
    StatusResponse::ok_with(data).into_response()
}

pub(crate) fn err(status: axum::http::StatusCode, msg: impl Into<Cow<'static, str>>) -> Response {
    StatusResponse::error_with_status(status, msg, None).with_status(status)
}

pub(crate) fn err_with_code(
    status: axum::http::StatusCode,
    msg: impl Into<Cow<'static, str>>,
    code: impl Into<Cow<'static, str>>,
) -> Response {
    StatusResponse::error_with_status(status, msg, Some(code.into())).with_status(status)
}

task_local! {
    static CURRENT_API_LOCALE: ApiLocale;
}

task_local! {
    static CURRENT_API_REQUEST_ID: String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiLocale {
    En,
    ZhCn,
}

impl ApiLocale {
    pub(crate) fn from_accept_language(raw: Option<&str>) -> Self {
        raw.and_then(Self::parse_accept_language)
            .unwrap_or(Self::En)
    }

    fn parse_accept_language(raw: &str) -> Option<Self> {
        raw.split(',')
            .map(|item| item.split(';').next().unwrap_or("").trim())
            .find_map(Self::parse)
    }

    fn parse(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized == "zh"
            || normalized.starts_with("zh-cn")
            || normalized.starts_with("zh_sg")
            || normalized.starts_with("zh-sg")
            || normalized.starts_with("zh_hans")
            || normalized.starts_with("zh-hans")
        {
            return Some(Self::ZhCn);
        }
        match normalized.as_str() {
            "en" | "en-us" | "en-gb" => Some(Self::En),
            _ if normalized.starts_with("en-") || normalized.starts_with("en_") => Some(Self::En),
            _ => None,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
        }
    }
}

pub(crate) async fn with_api_request_scope<F>(
    headers: &axum::http::HeaderMap,
    request_id: String,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    let locale = headers
        .get(ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .map_or(ApiLocale::En, |value| {
            ApiLocale::from_accept_language(Some(value))
        });
    CURRENT_API_REQUEST_ID
        .scope(request_id, async move {
            CURRENT_API_LOCALE.scope(locale, future).await
        })
        .await
}

fn current_api_locale() -> ApiLocale {
    CURRENT_API_LOCALE
        .try_with(|value| *value)
        .unwrap_or(ApiLocale::En)
}

fn current_api_request_id() -> Option<String> {
    CURRENT_API_REQUEST_ID.try_with(Clone::clone).ok()
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiProblemCategory {
    Validation,
    Auth,
    Permission,
    NotFound,
    Conflict,
    FeatureDisabled,
    RateLimit,
    TooBusy,
    Network,
    Upstream,
    Local,
    Internal,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ApiProblem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
    pub(crate) category: ApiProblemCategory,
    pub(crate) status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) localized_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) locale: Option<String>,
    pub(crate) retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
}

impl ApiProblem {
    pub(crate) fn from_legacy(
        status: StatusCode,
        detail: Option<&str>,
        explicit_code: Option<&str>,
    ) -> Option<Self> {
        let normalized_explicit_code = explicit_code
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let detail = detail
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let inferred = infer_problem_spec(status, explicit_code, detail.as_deref());
        let title = localized_problem_title(current_api_locale(), inferred.category).to_string();
        let localized_message =
            localized_problem_message(current_api_locale(), inferred, detail.as_deref())
                .map(str::to_string);
        let locale = localized_message
            .as_ref()
            .map(|_| current_api_locale().code().to_string());

        Some(Self {
            code: inferred
                .code
                .map(str::to_string)
                .or(normalized_explicit_code),
            category: inferred.category,
            status: status.as_u16(),
            title: Some(title),
            detail,
            localized_message,
            locale,
            retryable: inferred.retryable,
            request_id: current_api_request_id(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct InferredProblem {
    code: Option<&'static str>,
    category: ApiProblemCategory,
    retryable: bool,
}

fn infer_problem_spec(
    status: StatusCode,
    explicit_code: Option<&str>,
    detail: Option<&str>,
) -> InferredProblem {
    let normalized_code = explicit_code
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let normalized_detail = detail
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    if let Some(ref code) = normalized_code
        && let Some(inferred) = infer_problem_from_code(code.as_str())
    {
        return inferred;
    }

    if let Some(ref message) = normalized_detail
        && let Some(inferred) = infer_problem_from_detail(status, message.as_str())
    {
        return inferred;
    }

    infer_problem_from_status(status)
}

fn infer_problem_from_code(code: &str) -> Option<InferredProblem> {
    let inferred = match code {
        "authentication_failed" => InferredProblem {
            code: Some("authentication_failed"),
            category: ApiProblemCategory::Auth,
            retryable: false,
        },
        "device_key_not_found" => InferredProblem {
            code: Some("device_key_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        "channel_not_found" => InferredProblem {
            code: Some("channel_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        "device_not_found" => InferredProblem {
            code: Some("device_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        "invalid_channel_id" => InferredProblem {
            code: Some("invalid_channel_id"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "invalid_password" => InferredProblem {
            code: Some("invalid_password"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "invalid_device_token" => InferredProblem {
            code: Some("invalid_device_token"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "invalid_platform" => InferredProblem {
            code: Some("invalid_platform"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "event_time_required" => InferredProblem {
            code: Some("event_time_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "observed_at_required" => InferredProblem {
            code: Some("observed_at_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "provider_token_missing" => InferredProblem {
            code: Some("provider_token_missing"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "provider_token_required" => InferredProblem {
            code: Some("provider_token_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "password_mismatch" => InferredProblem {
            code: Some("password_mismatch"),
            category: ApiProblemCategory::Conflict,
            retryable: false,
        },
        "invalid_channel_password" => InferredProblem {
            code: Some("invalid_channel_password"),
            category: ApiProblemCategory::Conflict,
            retryable: false,
        },
        "platform_mismatch" => InferredProblem {
            code: Some("platform_mismatch"),
            category: ApiProblemCategory::Conflict,
            retryable: false,
        },
        "channel_type_mismatch" => InferredProblem {
            code: Some("channel_type_mismatch"),
            category: ApiProblemCategory::Conflict,
            retryable: false,
        },
        "private_channel_disabled" => InferredProblem {
            code: Some("private_channel_disabled"),
            category: ApiProblemCategory::FeatureDisabled,
            retryable: false,
        },
        "private_channel_runtime_unavailable" => InferredProblem {
            code: Some("private_channel_runtime_unavailable"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        "private_channel_unhealthy" => InferredProblem {
            code: Some("private_channel_unhealthy"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        "private_wss_transport_disabled" => InferredProblem {
            code: Some("private_wss_transport_disabled"),
            category: ApiProblemCategory::FeatureDisabled,
            retryable: false,
        },
        "missing_websocket_subprotocol" => InferredProblem {
            code: Some("missing_websocket_subprotocol"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "server_busy" => InferredProblem {
            code: Some("server_busy"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        "upstream_error" => InferredProblem {
            code: Some("upstream_error"),
            category: ApiProblemCategory::Upstream,
            retryable: true,
        },
        "internal_error" => InferredProblem {
            code: Some("internal_error"),
            category: ApiProblemCategory::Internal,
            retryable: true,
        },
        "store_error" => InferredProblem {
            code: Some("store_error"),
            category: ApiProblemCategory::Internal,
            retryable: true,
        },
        "route_not_found" => InferredProblem {
            code: Some("route_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        _ => return None,
    };
    Some(inferred)
}

fn infer_problem_from_detail(status: StatusCode, detail: &str) -> Option<InferredProblem> {
    let inferred = match detail {
        "authentication failed" => InferredProblem {
            code: Some("authentication_failed"),
            category: ApiProblemCategory::Auth,
            retryable: false,
        },
        "private channel is disabled" => InferredProblem {
            code: Some("private_channel_disabled"),
            category: ApiProblemCategory::FeatureDisabled,
            retryable: false,
        },
        "private channel runtime is unavailable" => InferredProblem {
            code: Some("private_channel_runtime_unavailable"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        "private channel unhealthy" => InferredProblem {
            code: Some("private_channel_unhealthy"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        "private wss transport is disabled" => InferredProblem {
            code: Some("private_wss_transport_disabled"),
            category: ApiProblemCategory::FeatureDisabled,
            retryable: false,
        },
        "404 not found" => InferredProblem {
            code: Some("route_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        "server is busy, please try again later" => InferredProblem {
            code: Some("server_busy"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        "invalid device token" => InferredProblem {
            code: Some("invalid_device_token"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "device not found" => InferredProblem {
            code: Some("device_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        "channel not found" => InferredProblem {
            code: Some("channel_not_found"),
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        "invalid channel password" => InferredProblem {
            code: Some("password_mismatch"),
            category: ApiProblemCategory::Conflict,
            retryable: false,
        },
        "channel name must not be empty" => InferredProblem {
            code: Some("invalid_channel_name"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "channel id must not be empty" => InferredProblem {
            code: Some("channel_id_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "password is required" => InferredProblem {
            code: Some("password_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "event_id is required" => InferredProblem {
            code: Some("event_id_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "thing_id is required" => InferredProblem {
            code: Some("thing_id_required"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "event_id is generated by gateway on /event/create" => InferredProblem {
            code: Some("event_id_forbidden_on_create"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "thing_id is generated by gateway on /thing/create" => InferredProblem {
            code: Some("thing_id_forbidden_on_create"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "created_at is only allowed on /thing/create" => InferredProblem {
            code: Some("created_at_forbidden_on_update"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "channels exceeds max limit 2000" => InferredProblem {
            code: Some("channels_limit_exceeded"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "channel subscriber limit exceeded" => InferredProblem {
            code: Some("channel_subscriber_limit_exceeded"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "invalid platform" => InferredProblem {
            code: Some("invalid_platform"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "database error, please try again later" => InferredProblem {
            code: Some("store_error"),
            category: ApiProblemCategory::Internal,
            retryable: true,
        },
        "must provide either channel_id or channel_name" => InferredProblem {
            code: Some("channel_binding_invalid"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        "device route is provider; provider_token required (switch route to private for private channel ops)" => {
            InferredProblem {
                code: Some("provider_token_required"),
                category: ApiProblemCategory::Validation,
                retryable: false,
            }
        }
        _ if detail.starts_with("missing websocket subprotocol") => InferredProblem {
            code: Some("missing_websocket_subprotocol"),
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        _ => return Some(infer_problem_from_status(status)),
    };
    Some(inferred)
}

fn infer_problem_from_status(status: StatusCode) -> InferredProblem {
    match status {
        StatusCode::UNAUTHORIZED => InferredProblem {
            code: Some("authentication_failed"),
            category: ApiProblemCategory::Auth,
            retryable: false,
        },
        StatusCode::FORBIDDEN => InferredProblem {
            code: None,
            category: ApiProblemCategory::Permission,
            retryable: false,
        },
        StatusCode::NOT_FOUND => InferredProblem {
            code: None,
            category: ApiProblemCategory::NotFound,
            retryable: false,
        },
        StatusCode::TOO_MANY_REQUESTS => InferredProblem {
            code: None,
            category: ApiProblemCategory::RateLimit,
            retryable: true,
        },
        StatusCode::SERVICE_UNAVAILABLE => InferredProblem {
            code: Some("server_busy"),
            category: ApiProblemCategory::TooBusy,
            retryable: true,
        },
        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => InferredProblem {
            code: Some("upstream_error"),
            category: ApiProblemCategory::Upstream,
            retryable: true,
        },
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => InferredProblem {
            code: None,
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
        _ if status.is_server_error() => InferredProblem {
            code: Some("internal_error"),
            category: ApiProblemCategory::Internal,
            retryable: true,
        },
        _ => InferredProblem {
            code: None,
            category: ApiProblemCategory::Validation,
            retryable: false,
        },
    }
}

fn localized_problem_title(locale: ApiLocale, category: ApiProblemCategory) -> &'static str {
    match (locale, category) {
        (ApiLocale::En, ApiProblemCategory::Validation) => "Validation failed",
        (ApiLocale::ZhCn, ApiProblemCategory::Validation) => "请求参数有误",
        (ApiLocale::En, ApiProblemCategory::Auth) => "Authentication failed",
        (ApiLocale::ZhCn, ApiProblemCategory::Auth) => "认证失败",
        (ApiLocale::En, ApiProblemCategory::Permission) => "Permission denied",
        (ApiLocale::ZhCn, ApiProblemCategory::Permission) => "权限不足",
        (ApiLocale::En, ApiProblemCategory::NotFound) => "Resource not found",
        (ApiLocale::ZhCn, ApiProblemCategory::NotFound) => "资源不存在",
        (ApiLocale::En, ApiProblemCategory::Conflict) => "Request conflicts with current state",
        (ApiLocale::ZhCn, ApiProblemCategory::Conflict) => "请求与当前状态冲突",
        (ApiLocale::En, ApiProblemCategory::FeatureDisabled) => "Feature unavailable",
        (ApiLocale::ZhCn, ApiProblemCategory::FeatureDisabled) => "功能不可用",
        (ApiLocale::En, ApiProblemCategory::RateLimit) => "Too many requests",
        (ApiLocale::ZhCn, ApiProblemCategory::RateLimit) => "请求过于频繁",
        (ApiLocale::En, ApiProblemCategory::TooBusy) => "Service temporarily unavailable",
        (ApiLocale::ZhCn, ApiProblemCategory::TooBusy) => "服务暂时不可用",
        (ApiLocale::En, ApiProblemCategory::Network) => "Network unavailable",
        (ApiLocale::ZhCn, ApiProblemCategory::Network) => "网络不可用",
        (ApiLocale::En, ApiProblemCategory::Upstream) => "Upstream service failed",
        (ApiLocale::ZhCn, ApiProblemCategory::Upstream) => "上游服务异常",
        (ApiLocale::En, ApiProblemCategory::Local) => "Local operation failed",
        (ApiLocale::ZhCn, ApiProblemCategory::Local) => "本地操作失败",
        (ApiLocale::En, ApiProblemCategory::Internal) => "Internal server error",
        (ApiLocale::ZhCn, ApiProblemCategory::Internal) => "服务内部错误",
    }
}

fn localized_problem_message(
    locale: ApiLocale,
    inferred: InferredProblem,
    detail: Option<&str>,
) -> Option<&'static str> {
    match (locale, inferred.code) {
        (ApiLocale::En, Some("authentication_failed")) => {
            Some("Gateway authentication failed. Please verify the server token.")
        }
        (ApiLocale::ZhCn, Some("authentication_failed")) => {
            Some("网关认证失败，请检查服务器令牌。")
        }
        (ApiLocale::En, Some("device_key_not_found")) => {
            Some("This device registration is no longer valid. Please retry.")
        }
        (ApiLocale::ZhCn, Some("device_key_not_found")) => Some("当前设备注册已失效，请重试。"),
        (ApiLocale::En, Some("device_not_found")) => {
            Some("This device route no longer exists. Please retry.")
        }
        (ApiLocale::ZhCn, Some("device_not_found")) => Some("当前设备路由已失效，请重试。"),
        (ApiLocale::En, Some("invalid_channel_id")) => {
            Some("The channel ID format is invalid. Please check and retry.")
        }
        (ApiLocale::ZhCn, Some("invalid_channel_id")) => Some("频道 ID 格式不正确，请检查后重试。"),
        (ApiLocale::En, Some("invalid_password")) => {
            Some("The channel password format is invalid. Please check and retry.")
        }
        (ApiLocale::ZhCn, Some("invalid_password")) => Some("频道密码格式不正确，请检查后重试。"),
        (ApiLocale::En, Some("password_mismatch"))
        | (ApiLocale::En, Some("invalid_channel_password")) => {
            Some("The channel password is incorrect. Please verify it and try again.")
        }
        (ApiLocale::ZhCn, Some("password_mismatch"))
        | (ApiLocale::ZhCn, Some("invalid_channel_password")) => {
            Some("频道密码不正确，请检查后重试。")
        }
        (ApiLocale::En, Some("channel_not_found")) => {
            Some("The channel does not exist or is no longer available. Please refresh and retry.")
        }
        (ApiLocale::ZhCn, Some("channel_not_found")) => Some("频道不存在或已失效，请刷新后重试。"),
        (ApiLocale::En, Some("private_channel_disabled")) => {
            Some("Private channel is disabled on this gateway. Please use the system push channel.")
        }
        (ApiLocale::ZhCn, Some("private_channel_disabled")) => {
            Some("当前网关未开启私有通道，请改用系统推送通道。")
        }
        (ApiLocale::En, Some("private_channel_runtime_unavailable")) => {
            Some("Private channel is temporarily unavailable. Please retry later.")
        }
        (ApiLocale::ZhCn, Some("private_channel_runtime_unavailable")) => {
            Some("当前私有通道暂时不可用，请稍后重试。")
        }
        (ApiLocale::En, Some("private_channel_unhealthy")) => {
            Some("Private channel health is degraded. Please retry later.")
        }
        (ApiLocale::ZhCn, Some("private_channel_unhealthy")) => {
            Some("当前私有通道状态异常，请稍后重试。")
        }
        (ApiLocale::En, Some("private_wss_transport_disabled")) => {
            Some("Private WebSocket transport is disabled on this gateway.")
        }
        (ApiLocale::ZhCn, Some("private_wss_transport_disabled")) => {
            Some("当前网关未开启私有 WebSocket 通道。")
        }
        (ApiLocale::En, Some("missing_websocket_subprotocol")) => {
            Some("The private WebSocket request is missing the required subprotocol.")
        }
        (ApiLocale::ZhCn, Some("missing_websocket_subprotocol")) => {
            Some("当前私有 WebSocket 请求缺少必需的子协议。")
        }
        (ApiLocale::En, Some("provider_token_missing"))
        | (ApiLocale::En, Some("provider_token_required")) => {
            Some("The device push route is not ready yet. Please retry after refreshing the route.")
        }
        (ApiLocale::ZhCn, Some("provider_token_missing"))
        | (ApiLocale::ZhCn, Some("provider_token_required")) => {
            Some("当前设备推送通道尚未就绪，请刷新设备路由后重试。")
        }
        (ApiLocale::En, Some("platform_mismatch"))
        | (ApiLocale::En, Some("channel_type_mismatch")) => {
            Some("The device binding has changed. Please retry with the latest route.")
        }
        (ApiLocale::ZhCn, Some("platform_mismatch"))
        | (ApiLocale::ZhCn, Some("channel_type_mismatch")) => {
            Some("当前设备绑定信息已变化，请使用最新路由重试。")
        }
        (ApiLocale::En, Some("invalid_device_token")) => {
            Some("The push token is invalid. Please refresh it and try again.")
        }
        (ApiLocale::ZhCn, Some("invalid_device_token")) => {
            Some("设备推送令牌无效，请重新获取后重试。")
        }
        (ApiLocale::En, Some("invalid_platform")) => Some("The platform field is invalid."),
        (ApiLocale::ZhCn, Some("invalid_platform")) => Some("平台字段无效。"),
        (ApiLocale::En, Some("invalid_channel_name")) => {
            Some("The channel name must not be empty.")
        }
        (ApiLocale::ZhCn, Some("invalid_channel_name")) => Some("频道名称不能为空。"),
        (ApiLocale::En, Some("channel_id_required")) => Some("The channel ID is required."),
        (ApiLocale::ZhCn, Some("channel_id_required")) => Some("频道 ID 不能为空。"),
        (ApiLocale::En, Some("password_required")) => Some("The channel password is required."),
        (ApiLocale::ZhCn, Some("password_required")) => Some("频道密码不能为空。"),
        (ApiLocale::En, Some("event_id_required")) => Some("The event ID is required."),
        (ApiLocale::ZhCn, Some("event_id_required")) => Some("事件 ID 不能为空。"),
        (ApiLocale::En, Some("thing_id_required")) => Some("The thing ID is required."),
        (ApiLocale::ZhCn, Some("thing_id_required")) => Some("对象 ID 不能为空。"),
        (ApiLocale::En, Some("event_id_forbidden_on_create")) => {
            Some("Do not provide an event ID when creating a new event.")
        }
        (ApiLocale::ZhCn, Some("event_id_forbidden_on_create")) => {
            Some("创建事件时无需提供事件 ID。")
        }
        (ApiLocale::En, Some("thing_id_forbidden_on_create")) => {
            Some("Do not provide a thing ID when creating a new thing.")
        }
        (ApiLocale::ZhCn, Some("thing_id_forbidden_on_create")) => {
            Some("创建对象时无需提供对象 ID。")
        }
        (ApiLocale::En, Some("created_at_forbidden_on_update")) => {
            Some("The created_at field is only allowed when creating a thing.")
        }
        (ApiLocale::ZhCn, Some("created_at_forbidden_on_update")) => {
            Some("created_at 仅允许在创建对象时传入。")
        }
        (ApiLocale::En, Some("channels_limit_exceeded")) => {
            Some("Too many channels were submitted in one request. Please split the sync batch.")
        }
        (ApiLocale::ZhCn, Some("channels_limit_exceeded")) => {
            Some("单次同步的频道数量过多，请拆分后重试。")
        }
        (ApiLocale::En, Some("channel_subscriber_limit_exceeded")) => Some(
            "This channel already has 32 subscribers. Remove an unused subscriber before adding another device.",
        ),
        (ApiLocale::ZhCn, Some("channel_subscriber_limit_exceeded")) => {
            Some("该频道已达到 32 个订阅者上限，请先移除不再使用的设备。")
        }
        (ApiLocale::En, Some("channel_binding_invalid")) => {
            Some("Provide either a channel ID or a channel name, but not both.")
        }
        (ApiLocale::ZhCn, Some("channel_binding_invalid")) => {
            Some("请在频道 ID 和频道名称之间二选一填写，不能同时为空或同时提供。")
        }
        (ApiLocale::En, Some("server_busy")) => Some("The service is busy. Please retry later."),
        (ApiLocale::ZhCn, Some("server_busy")) => Some("服务繁忙，请稍后重试。"),
        (ApiLocale::En, Some("route_not_found")) => {
            Some("The requested API route does not exist on this gateway.")
        }
        (ApiLocale::ZhCn, Some("route_not_found")) => Some("当前网关不存在该 API 路由。"),
        (ApiLocale::En, Some("upstream_error")) => {
            Some("An upstream service is temporarily unavailable. Please retry later.")
        }
        (ApiLocale::ZhCn, Some("upstream_error")) => Some("上游服务暂时异常，请稍后重试。"),
        (ApiLocale::En, Some("internal_error")) | (ApiLocale::En, Some("store_error")) => {
            Some("The service is temporarily unavailable. Please retry later.")
        }
        (ApiLocale::ZhCn, Some("internal_error")) | (ApiLocale::ZhCn, Some("store_error")) => {
            Some("服务暂时异常，请稍后重试。")
        }
        _ => localized_problem_message_by_category(locale, inferred.category, detail),
    }
}

fn localized_problem_message_by_category(
    locale: ApiLocale,
    category: ApiProblemCategory,
    _detail: Option<&str>,
) -> Option<&'static str> {
    match (locale, category) {
        (ApiLocale::En, ApiProblemCategory::Validation) => {
            Some("The request is invalid. Please check the input and retry.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::Validation) => Some("请求参数有误，请检查后重试。"),
        (ApiLocale::En, ApiProblemCategory::Auth)
        | (ApiLocale::En, ApiProblemCategory::Permission) => {
            Some("Gateway authentication failed. Please verify the server token.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::Auth)
        | (ApiLocale::ZhCn, ApiProblemCategory::Permission) => {
            Some("网关认证失败，请检查服务器令牌。")
        }
        (ApiLocale::En, ApiProblemCategory::NotFound) => {
            Some("The requested resource does not exist or is no longer available.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::NotFound) => Some("请求的资源不存在或已失效。"),
        (ApiLocale::En, ApiProblemCategory::Conflict) => {
            Some("The request conflicts with the current server state.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::Conflict) => Some("当前请求与服务端状态冲突。"),
        (ApiLocale::En, ApiProblemCategory::FeatureDisabled) => {
            Some("This feature is not enabled on the gateway.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::FeatureDisabled) => Some("当前网关未开启该功能。"),
        (ApiLocale::En, ApiProblemCategory::RateLimit)
        | (ApiLocale::En, ApiProblemCategory::TooBusy)
        | (ApiLocale::En, ApiProblemCategory::Upstream)
        | (ApiLocale::En, ApiProblemCategory::Internal) => {
            Some("The service is temporarily unavailable. Please retry later.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::RateLimit)
        | (ApiLocale::ZhCn, ApiProblemCategory::TooBusy)
        | (ApiLocale::ZhCn, ApiProblemCategory::Upstream)
        | (ApiLocale::ZhCn, ApiProblemCategory::Internal) => Some("服务暂时异常，请稍后重试。"),
        (ApiLocale::En, ApiProblemCategory::Network) => {
            Some("The network is unavailable. Please retry later.")
        }
        (ApiLocale::ZhCn, ApiProblemCategory::Network) => Some("网络暂时不可用，请稍后重试。"),
        (ApiLocale::En, ApiProblemCategory::Local) => Some("The local operation failed."),
        (ApiLocale::ZhCn, ApiProblemCategory::Local) => Some("本地操作失败。"),
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("validation failed: {message}")]
    Validation {
        message: Cow<'static, str>,
        code: Option<Cow<'static, str>>,
    },
    #[error("invalid credentials or unauthorized")]
    Unauthorized,
    #[error("upstream {provider} error (HTTP {status}): {message}")]
    Upstream {
        provider: &'static str,
        status: u16,
        message: String,
    },
    #[error("internal error: {0}")]
    Internal(String),
    #[error("server is too busy")]
    TooBusy,
    #[error(transparent)]
    StoreError(#[from] StoreError),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        emit_api_error_observation(&self);
        match self {
            Error::Validation { message, code } => match code {
                Some(code) => {
                    StatusResponse::error_with_status(StatusCode::BAD_REQUEST, message, Some(code))
                        .with_status(StatusCode::BAD_REQUEST)
                }
                None => err(StatusCode::BAD_REQUEST, message),
            },
            Error::Unauthorized => StatusResponse::error_with_status(
                StatusCode::UNAUTHORIZED,
                "authentication failed",
                Some(Cow::Borrowed("authentication_failed")),
            )
            .with_status(StatusCode::UNAUTHORIZED),
            Error::TooBusy => err_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "server is busy, please try again later",
                "server_busy",
            ),
            Error::Upstream { message, .. } => StatusResponse::error_with_status(
                StatusCode::BAD_GATEWAY,
                message,
                Some(Cow::Borrowed("upstream_error")),
            )
            .with_status(StatusCode::BAD_GATEWAY),
            Error::Internal(msg) => StatusResponse::error_with_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg,
                Some(Cow::Borrowed("internal_error")),
            )
            .with_status(StatusCode::INTERNAL_SERVER_ERROR),
            Error::StoreError(StoreError::InvalidDeviceToken) => StatusResponse::error_with_status(
                StatusCode::BAD_REQUEST,
                "invalid device token",
                Some(Cow::Borrowed("invalid_device_token")),
            )
            .with_status(StatusCode::BAD_REQUEST),
            Error::StoreError(StoreError::DeviceNotFound) => StatusResponse::error_with_status(
                StatusCode::BAD_REQUEST,
                "device not found",
                Some(Cow::Borrowed("device_not_found")),
            )
            .with_status(StatusCode::BAD_REQUEST),
            Error::StoreError(StoreError::ChannelNotFound) => StatusResponse::error_with_status(
                StatusCode::NOT_FOUND,
                "channel not found",
                Some(Cow::Borrowed("channel_not_found")),
            )
            .with_status(StatusCode::NOT_FOUND),
            Error::StoreError(StoreError::ChannelPasswordMismatch) => {
                StatusResponse::error_with_status(
                    StatusCode::FORBIDDEN,
                    "invalid channel password",
                    Some(Cow::Borrowed("password_mismatch")),
                )
                .with_status(StatusCode::FORBIDDEN)
            }
            Error::StoreError(StoreError::ChannelAliasMissing) => {
                StatusResponse::error_with_status(
                    StatusCode::BAD_REQUEST,
                    "channel name must not be empty",
                    Some(Cow::Borrowed("invalid_channel_name")),
                )
                .with_status(StatusCode::BAD_REQUEST)
            }
            Error::StoreError(StoreError::ChannelSubscriberLimitExceeded) => {
                StatusResponse::error_with_status(
                    StatusCode::BAD_REQUEST,
                    "channel subscriber limit exceeded",
                    Some(Cow::Borrowed("channel_subscriber_limit_exceeded")),
                )
                .with_status(StatusCode::BAD_REQUEST)
            }
            Error::StoreError(StoreError::InvalidPlatform) => StatusResponse::error_with_status(
                StatusCode::BAD_REQUEST,
                "invalid platform",
                Some(Cow::Borrowed("invalid_platform")),
            )
            .with_status(StatusCode::BAD_REQUEST),
            Error::StoreError(_) => err_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error, please try again later",
                "store_error",
            ),
        }
    }
}

fn emit_api_error_observation(error: &Error) {
    let (status_code, error_kind, error_code): (u16, &'static str, Option<&str>) = match error {
        Error::Validation { code, .. } => (
            StatusCode::BAD_REQUEST.as_u16(),
            "validation",
            code.as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ),
        Error::Unauthorized => (
            StatusCode::UNAUTHORIZED.as_u16(),
            "unauthorized",
            Some("authentication_failed"),
        ),
        Error::TooBusy => (
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            "too_busy",
            Some("server_busy"),
        ),
        Error::Upstream { .. } => (
            StatusCode::BAD_GATEWAY.as_u16(),
            "upstream",
            Some("upstream_error"),
        ),
        Error::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            "internal",
            Some("internal_error"),
        ),
        Error::StoreError(StoreError::InvalidDeviceToken) => (
            StatusCode::BAD_REQUEST.as_u16(),
            "store_error",
            Some("invalid_device_token"),
        ),
        Error::StoreError(StoreError::DeviceNotFound) => (
            StatusCode::BAD_REQUEST.as_u16(),
            "store_error",
            Some("device_not_found"),
        ),
        Error::StoreError(StoreError::ChannelNotFound) => (
            StatusCode::NOT_FOUND.as_u16(),
            "store_error",
            Some("channel_not_found"),
        ),
        Error::StoreError(StoreError::ChannelPasswordMismatch) => (
            StatusCode::FORBIDDEN.as_u16(),
            "store_error",
            Some("password_mismatch"),
        ),
        Error::StoreError(StoreError::ChannelAliasMissing) => (
            StatusCode::BAD_REQUEST.as_u16(),
            "store_error",
            Some("invalid_channel_name"),
        ),
        Error::StoreError(StoreError::ChannelSubscriberLimitExceeded) => (
            StatusCode::BAD_REQUEST.as_u16(),
            "store_error",
            Some("channel_subscriber_limit_exceeded"),
        ),
        Error::StoreError(StoreError::InvalidPlatform) => (
            StatusCode::BAD_REQUEST.as_u16(),
            "store_error",
            Some("invalid_platform"),
        ),
        Error::StoreError(_) => (
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            "store_error",
            Some("store_error"),
        ),
    };

    let request_id = current_api_request_id();
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "api.error_response",
        status_code = (u64::from(status_code)),
        error_kind = %(error_kind),
        error_code = ?error_code,
        request_id = ?request_id.as_deref().map(crate::util::redact_text)
    );
}

impl Error {
    pub fn validation(msg: impl Into<Cow<'static, str>>) -> Self {
        Error::Validation {
            message: msg.into(),
            code: None,
        }
    }

    pub fn validation_code(
        msg: impl Into<Cow<'static, str>>,
        code: impl Into<Cow<'static, str>>,
    ) -> Self {
        Error::Validation {
            message: msg.into(),
            code: Some(code.into()),
        }
    }

    pub(crate) fn from_json_rejection(rejection: JsonRejection) -> Self {
        match rejection {
            JsonRejection::MissingJsonContentType(_) => Self::validation_code(
                "missing Content-Type: application/json",
                "missing_json_content_type",
            ),
            JsonRejection::JsonSyntaxError(err) => Self::validation_code(
                format!("invalid JSON syntax: {}", err),
                "invalid_json_syntax",
            ),
            JsonRejection::JsonDataError(err) => {
                Self::validation_code(format!("invalid JSON data: {}", err), "invalid_json_data")
            }
            JsonRejection::BytesRejection(err) => Self::validation_code(
                format!("invalid request body: {}", err),
                "invalid_request_body",
            ),
            _ => Self::validation_code("invalid JSON request", "invalid_json_request"),
        }
    }
}

impl From<ValueError> for Error {
    fn from(value: ValueError) -> Self {
        Self::validation(value.to_string())
    }
}

pub(crate) type HttpResult = Result<Response, Error>;

#[derive(Serialize)]
pub(crate) struct StatusResponse<T = ()> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<ApiProblem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> IntoResponse for StatusResponse<T> {
    fn into_response(self) -> Response {
        self.into_response_with_status(StatusCode::OK)
    }
}

impl<T: Serialize> StatusResponse<T> {
    pub(crate) fn with_status(self, status: axum::http::StatusCode) -> Response {
        self.into_response_with_status(status)
    }

    fn into_response_with_status(mut self, status: StatusCode) -> Response {
        if !self.success && self.problem.is_none() {
            self.problem =
                ApiProblem::from_legacy(status, self.error.as_deref(), self.error_code.as_deref());
        }
        let content_language = self
            .problem
            .as_ref()
            .and_then(|problem| problem.locale.as_deref())
            .map(str::to_string);
        let request_id = current_api_request_id();
        let mut response = (status, axum::Json(self)).into_response();
        if let Some(locale) = content_language
            && let Ok(value) = HeaderValue::from_str(&locale)
        {
            response.headers_mut().insert(CONTENT_LANGUAGE, value);
        }
        if let Some(request_id) = request_id
            && let Ok(value) = HeaderValue::from_str(&request_id)
        {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        response
    }

    pub(crate) fn ok_with(data: T) -> Self {
        Self {
            success: true,
            error: None,
            error_code: None,
            problem: None,
            data: Some(data),
        }
    }
}

impl StatusResponse {
    fn error_with_status(
        status: StatusCode,
        msg: impl Into<Cow<'static, str>>,
        explicit_code: Option<Cow<'static, str>>,
    ) -> Self {
        let error = msg.into();
        let error_code = explicit_code.or_else(|| {
            ApiProblem::from_legacy(status, Some(error.as_ref()), None)
                .and_then(|problem| problem.code.map(Cow::Owned))
        });
        let problem = ApiProblem::from_legacy(status, Some(error.as_ref()), error_code.as_deref());
        Self {
            success: false,
            error: Some(error),
            error_code,
            problem,
            data: None,
        }
    }

    pub(crate) fn err_with_data<T: Serialize>(
        msg: impl Into<Cow<'static, str>>,
        data: T,
    ) -> StatusResponse<T> {
        let error = msg.into();
        StatusResponse {
            success: false,
            error_code: ApiProblem::from_legacy(
                StatusCode::BAD_REQUEST,
                Some(error.as_ref()),
                None,
            )
            .and_then(|problem| problem.code.map(Cow::Owned)),
            problem: ApiProblem::from_legacy(StatusCode::BAD_REQUEST, Some(error.as_ref()), None),
            error: Some(error),
            data: Some(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_validation_detail_maps_to_stable_problem_code() {
        let problem =
            ApiProblem::from_legacy(StatusCode::BAD_REQUEST, Some("event_id is required"), None)
                .expect("legacy validation problem should infer");
        assert_eq!(problem.code.as_deref(), Some("event_id_required"));
        assert!(matches!(problem.category, ApiProblemCategory::Validation));
    }

    #[test]
    fn legacy_limit_detail_maps_to_validation_problem_code() {
        let problem = ApiProblem::from_legacy(
            StatusCode::BAD_REQUEST,
            Some("channels exceeds max limit 2000"),
            None,
        )
        .expect("legacy limit problem should infer");
        assert_eq!(problem.code.as_deref(), Some("channels_limit_exceeded"));
        assert!(matches!(problem.category, ApiProblemCategory::Validation));
    }
}
