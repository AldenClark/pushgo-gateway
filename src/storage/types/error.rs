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
    #[error("Device not found")]
    DeviceNotFound,
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
    #[error("Channel subscriber limit exceeded")]
    ChannelSubscriberLimitExceeded,
    #[error(
        "Device route migration requires {pending} pending slots, but only {capacity} are available"
    )]
    RouteMigrationCapacityExceeded { pending: usize, capacity: usize },
    #[error("Provider dispatch durable capacity is exhausted ({pending}/{capacity})")]
    ProviderDispatchCapacityExceeded { pending: usize, capacity: usize },
    #[error("Dispatch submission durable capacity is exhausted ({pending}/{capacity})")]
    DispatchSubmissionCapacityExceeded { pending: usize, capacity: usize },
    #[error(
        "Legacy v12 has {pending} pending dispatch submission(s) without a durable acceptance order; drain them with the prior Gateway before retrying the forward fix"
    )]
    LegacyAcceptanceOrderPending { pending: usize },
    #[error("Private outbox durable capacity is exhausted ({pending}/{capacity})")]
    PrivateOutboxCapacityExceeded { pending: usize, capacity: usize },
    #[error("Private payload is missing after durable insert")]
    PrivatePayloadMissingAfterInsert,
    #[error("Database durability configuration is unsafe: {0}")]
    UnsafeDurabilityConfiguration(String),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("Password hash error: {0}")]
    PasswordHash(String),
    #[error("Password hashing capacity is exhausted")]
    PasswordKdfBusy,
    #[error("Schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: String, actual: String },
    #[error("Database upgrade failed: {0}")]
    Upgrade(String),
    #[cfg(test)]
    #[error("Injected test storage failure: {0}")]
    InjectedTestFailure(&'static str),
}

impl From<argon2::password_hash::Error> for StoreError {
    fn from(err: argon2::password_hash::Error) -> Self {
        StoreError::PasswordHash(err.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;
