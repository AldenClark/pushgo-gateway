use std::borrow::Cow;

use axum::{
    extract::rejection::JsonRejection,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::storage::StoreError;

pub(crate) fn ok<T: Serialize>(data: T) -> Response {
    StatusResponse::ok_with(data).into_response()
}

pub(crate) fn err(status: axum::http::StatusCode, msg: impl Into<Cow<'static, str>>) -> Response {
    StatusResponse::err(msg).with_status(status)
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
        use axum::http::StatusCode;

        match self {
            Error::Validation { message, code } => match code {
                Some(code) => StatusResponse::err_with_code(message, code)
                    .with_status(StatusCode::BAD_REQUEST),
                None => err(StatusCode::BAD_REQUEST, message),
            },
            Error::Unauthorized => err(StatusCode::UNAUTHORIZED, "authentication failed"),
            Error::TooBusy => err(
                StatusCode::SERVICE_UNAVAILABLE,
                "server is busy, please try again later",
            ),
            Error::Upstream { message, .. } => err(StatusCode::BAD_GATEWAY, message),
            Error::Internal(msg) => err(StatusCode::INTERNAL_SERVER_ERROR, msg),
            Error::StoreError(StoreError::InvalidDeviceToken) => {
                err(StatusCode::BAD_REQUEST, "invalid device token")
            }
            Error::StoreError(StoreError::DeviceNotFound) => {
                err(StatusCode::BAD_REQUEST, "device not found")
            }
            Error::StoreError(StoreError::ChannelNotFound) => {
                err(StatusCode::NOT_FOUND, "channel not found")
            }
            Error::StoreError(StoreError::ChannelPasswordMismatch) => {
                err(StatusCode::FORBIDDEN, "invalid channel password")
            }
            Error::StoreError(StoreError::ChannelAliasMissing) => {
                err(StatusCode::BAD_REQUEST, "channel name must not be empty")
            }
            Error::StoreError(StoreError::InvalidPlatform) => {
                err(StatusCode::BAD_REQUEST, "invalid platform")
            }
            Error::StoreError(_) => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error, please try again later",
            ),
        }
    }
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
            JsonRejection::MissingJsonContentType(_) => {
                Self::validation("missing Content-Type: application/json")
            }
            JsonRejection::JsonSyntaxError(err) => {
                Self::validation(format!("invalid JSON syntax: {}", err))
            }
            JsonRejection::JsonDataError(err) => {
                Self::validation(format!("invalid JSON data: {}", err))
            }
            JsonRejection::BytesRejection(err) => {
                Self::validation(format!("invalid request body: {}", err))
            }
            _ => Self::validation("invalid JSON request"),
        }
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
    pub data: Option<T>,
}

impl<T: Serialize> IntoResponse for StatusResponse<T> {
    fn into_response(self) -> Response {
        (axum::http::StatusCode::OK, axum::Json(self)).into_response()
    }
}

impl<T: Serialize> StatusResponse<T> {
    pub(crate) fn with_status(self, status: axum::http::StatusCode) -> Response {
        (status, axum::Json(self)).into_response()
    }

    pub(crate) fn ok_with(data: T) -> Self {
        Self {
            success: true,
            error: None,
            error_code: None,
            data: Some(data),
        }
    }
}

impl StatusResponse {
    pub(crate) fn err(msg: impl Into<Cow<'static, str>>) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            error_code: None,
            data: None,
        }
    }

    pub(crate) fn err_with_code(
        msg: impl Into<Cow<'static, str>>,
        code: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            success: false,
            error: Some(msg.into()),
            error_code: Some(code.into()),
            data: None,
        }
    }

    pub(crate) fn err_with_data<T: Serialize>(
        msg: impl Into<Cow<'static, str>>,
        data: T,
    ) -> StatusResponse<T> {
        StatusResponse {
            success: false,
            error: Some(msg.into()),
            error_code: None,
            data: Some(data),
        }
    }
}
