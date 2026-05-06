#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailureKind {
    Transport,
    CredentialsExpired,
    RateLimited,
    TemporarilyUnavailable,
    InvalidToken,
    PayloadTooLarge,
    Unauthorized,
    Rejected,
}

impl ProviderFailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::CredentialsExpired => "credentials_expired",
            Self::RateLimited => "rate_limited",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::PayloadTooLarge => "payload_too_large",
            Self::Unauthorized => "unauthorized",
            Self::Rejected => "rejected",
        }
    }

    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Transport | Self::RateLimited | Self::TemporarilyUnavailable
        )
    }

    pub const fn should_refresh_credentials(self) -> bool {
        matches!(self, Self::CredentialsExpired)
    }

    pub const fn is_invalid_token(self) -> bool {
        matches!(self, Self::InvalidToken)
    }

    pub const fn is_payload_too_large(self) -> bool {
        matches!(self, Self::PayloadTooLarge)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProviderFailure {
    pub(crate) status_code: u16,
    pub(crate) kind: ProviderFailureKind,
    pub(crate) message: String,
}

impl ProviderFailure {
    pub(crate) fn new(
        status_code: u16,
        kind: ProviderFailureKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status_code,
            kind,
            message: message.into(),
        }
    }
}

pub(crate) fn trimmed_body_text(body: &[u8]) -> Option<String> {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
