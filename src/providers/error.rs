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
            Self::Transport
                | Self::CredentialsExpired
                | Self::RateLimited
                | Self::TemporarilyUnavailable
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
    pub(crate) retry_after_millis: Option<i64>,
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
            retry_after_millis: None,
        }
    }

    pub(crate) fn with_retry_after_millis(mut self, retry_after_millis: Option<i64>) -> Self {
        self.retry_after_millis = retry_after_millis;
        self
    }
}

pub(crate) fn parse_retry_after_millis(value: Option<&str>) -> Option<i64> {
    parse_retry_after_millis_at(value, chrono::Utc::now().timestamp_millis())
}

fn parse_retry_after_millis_at(value: Option<&str>, now_millis: i64) -> Option<i64> {
    const MAX_RETRY_AFTER_SECONDS: u64 = 24 * 60 * 60;
    let raw = value?.trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return i64::try_from(seconds.min(MAX_RETRY_AFTER_SECONDS))
            .ok()?
            .checked_mul(1_000);
    }
    let target = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    let delay = target.timestamp_millis().saturating_sub(now_millis);
    (delay > 0).then_some(delay.min((MAX_RETRY_AFTER_SECONDS * 1_000) as i64))
}

pub(crate) fn trimmed_body_text(body: &[u8]) -> Option<String> {
    let trimmed = String::from_utf8_lossy(body).trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_retry_after_millis, parse_retry_after_millis_at};

    #[test]
    fn retry_after_delta_seconds_is_bounded_and_malformed_values_are_ignored() {
        assert_eq!(parse_retry_after_millis(Some("15")), Some(15_000));
        assert_eq!(
            parse_retry_after_millis(Some("999999")),
            Some(24 * 60 * 60 * 1_000)
        );
        assert_eq!(parse_retry_after_millis(Some("not-a-delay")), None);
    }

    #[test]
    fn retry_after_http_date_is_supported_and_bounded() {
        let now = 784_111_777_000_i64;
        assert_eq!(
            parse_retry_after_millis_at(Some("Sun, 06 Nov 1994 08:49:47 GMT"), now),
            Some(10_000)
        );
        assert_eq!(
            parse_retry_after_millis_at(Some("Sun, 06 Nov 1994 08:49:27 GMT"), now),
            None
        );
    }
}
