use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Unsupported database type: {0}")]
    InvalidDatabaseType(String),
    #[error("Database URL is required for {0}")]
    MissingDatabaseUrl(&'static str),
    #[error("Async runtime is not available")]
    RuntimeUnavailable,
    #[error("Invalid device token")]
    InvalidDeviceToken,
    #[error("Invalid platform")]
    InvalidPlatform,
    #[error("Binary Error")]
    BinaryError,
    #[error("Channel not found")]
    ChannelNotFound,
    #[error("Channel password mismatch")]
    ChannelPasswordMismatch,
    #[error("Channel alias missing")]
    ChannelAliasMissing,
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Password hash error: {0}")]
    PasswordHash(String),
    #[error("Schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: String, actual: String },
}

impl From<argon2::password_hash::Error> for StoreError {
    fn from(err: argon2::password_hash::Error) -> Self {
        StoreError::PasswordHash(err.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
