use super::{ValueError, ValueResult};

const MAX_EVENT_STATUS_LEN: usize = 24;
const MAX_EVENT_MESSAGE_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventSeverity {
    Critical,
    High,
    Normal,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventStatusText(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventMessageText(String);

impl EventSeverity {
    pub(crate) fn parse(raw: &str) -> ValueResult<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "normal" => Ok(Self::Normal),
            "low" => Ok(Self::Low),
            _ => Err(ValueError::new(
                "severity must be one of critical/high/normal/low",
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Normal => "normal",
            Self::Low => "low",
        }
    }
}

impl EventStatusText {
    pub(crate) fn parse(raw: &str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new("status must not be empty"));
        }
        if trimmed.chars().count() > MAX_EVENT_STATUS_LEN {
            return Err(ValueError::new("status is too long"));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl EventMessageText {
    pub(crate) fn parse(raw: &str) -> ValueResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValueError::new("message must not be empty"));
        }
        if trimmed.chars().count() > MAX_EVENT_MESSAGE_LEN {
            return Err(ValueError::new("message is too long"));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}
