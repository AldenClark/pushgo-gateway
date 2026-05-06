#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntityKind {
    Message,
    Event,
    Thing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotificationSeverity {
    Critical,
    High,
    Normal,
    Low,
}

impl EntityKind {
    pub(crate) fn detect(raw: Option<&str>) -> Self {
        match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
            "event" => Self::Event,
            "thing" => Self::Thing,
            _ => Self::Message,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Event => "event",
            Self::Thing => "thing",
        }
    }

    pub(crate) fn includes_event_id(self) -> bool {
        matches!(self, Self::Event | Self::Thing)
    }

    pub(crate) fn includes_thing_id(self) -> bool {
        matches!(self, Self::Thing)
    }
}

impl NotificationSeverity {
    pub(crate) fn normalize(raw: Option<String>) -> Self {
        raw.as_deref()
            .and_then(Self::parse_known)
            .unwrap_or(Self::Normal)
    }

    pub(crate) fn parse_known(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "normal" => Some(Self::Normal),
            "low" => Some(Self::Low),
            _ => None,
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

    pub(crate) fn fcm_priority(self) -> &'static str {
        match self {
            Self::Critical | Self::High | Self::Normal => "HIGH",
            Self::Low => "NORMAL",
        }
    }

    pub(crate) fn wns_priority(self) -> u8 {
        match self {
            Self::Critical | Self::High => 1,
            Self::Normal => 2,
            Self::Low => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EntityKind, NotificationSeverity};

    #[test]
    fn entity_kind_detects_known_types_and_defaults_to_message() {
        assert_eq!(EntityKind::detect(Some(" event ")), EntityKind::Event);
        assert_eq!(EntityKind::detect(Some("THING")), EntityKind::Thing);
        assert_eq!(EntityKind::detect(Some("custom")), EntityKind::Message);
        assert_eq!(EntityKind::detect(None), EntityKind::Message);
    }

    #[test]
    fn notification_severity_normalizes_and_exposes_provider_priorities() {
        assert_eq!(
            NotificationSeverity::normalize(Some("HIGH".to_string())),
            NotificationSeverity::High
        );
        assert_eq!(
            NotificationSeverity::normalize(Some(" critical ".to_string())),
            NotificationSeverity::Critical
        );
        assert_eq!(
            NotificationSeverity::normalize(Some("unknown".to_string())),
            NotificationSeverity::Normal
        );
        assert_eq!(NotificationSeverity::parse_known("unknown"), None);
        assert_eq!(NotificationSeverity::Normal.fcm_priority(), "HIGH");
        assert_eq!(NotificationSeverity::Low.fcm_priority(), "NORMAL");
        assert_eq!(NotificationSeverity::Critical.wns_priority(), 1);
        assert_eq!(NotificationSeverity::Normal.wns_priority(), 2);
        assert_eq!(NotificationSeverity::Low.wns_priority(), 3);
    }
}
