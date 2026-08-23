use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum CoreError {
    #[error("{message}")]
    Validation { message: String, code: &'static str },
    #[error("{message}")]
    Conflict { message: String, code: &'static str },
    #[error("{message}")]
    Auth { message: String, code: &'static str },
    #[error("server is busy, please try again later")]
    TooBusy,
    #[error("{0}")]
    Store(String),
    #[error("{0}")]
    Internal(String),
}

impl CoreError {
    pub(crate) fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
            code: "validation_failed",
        }
    }

    pub(crate) fn validation_code(message: impl Into<String>, code: &'static str) -> Self {
        Self::Validation {
            message: message.into(),
            code,
        }
    }

    pub(crate) fn auth(message: impl Into<String>, code: &'static str) -> Self {
        Self::Auth {
            message: message.into(),
            code,
        }
    }

    pub(crate) fn conflict(message: impl Into<String>, code: &'static str) -> Self {
        Self::Conflict {
            message: message.into(),
            code,
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl From<crate::value::ValueError> for CoreError {
    fn from(value: crate::value::ValueError) -> Self {
        Self::validation(value.to_string())
    }
}

impl From<crate::storage::StoreError> for CoreError {
    fn from(value: crate::storage::StoreError) -> Self {
        match value {
            crate::storage::StoreError::PasswordKdfBusy => Self::TooBusy,
            other => Self::Store(other.to_string()),
        }
    }
}
