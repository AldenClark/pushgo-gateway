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
            crate::storage::StoreError::Ordinary(error) => Self::from(error),
            crate::storage::StoreError::OperationScopeConflict => Self::conflict(
                "op_id is already used by a different operation",
                "op_id_scope_conflict",
            ),
            crate::storage::StoreError::PasswordKdfBusy => Self::TooBusy,
            other => Self::Store(other.to_string()),
        }
    }
}

impl From<crate::ordinary::KernelError> for CoreError {
    fn from(error: crate::ordinary::KernelError) -> Self {
        use crate::ordinary::KernelError;
        match error {
            KernelError::Control {
                status: 400,
                message,
                code,
            } => Self::validation_code(message, code),
            KernelError::Control {
                status: 409,
                message,
                code,
            } => Self::conflict(message, code),
            KernelError::Conflict => {
                Self::conflict("operation fingerprint conflict", "op_id_payload_conflict")
            }
            KernelError::ScopeConflict => Self::conflict(
                "op_id is already used by a different operation",
                "op_id_scope_conflict",
            ),
            KernelError::Invalid(message) => Self::validation(message),
            KernelError::Capacity | KernelError::Unavailable => Self::TooBusy,
            KernelError::Unauthorized => {
                Self::auth("channel not authorized", "channel_not_authorized")
            }
            other => Self::Store(other.to_string()),
        }
    }
}
