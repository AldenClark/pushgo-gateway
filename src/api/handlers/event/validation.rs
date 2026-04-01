use crate::{api::Error, storage::EventState};

use super::{EventProfile, EventRouteAction};

pub(super) fn normalize_event_severity(raw: &str) -> Result<String, Error> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "critical" | "high" | "normal" | "low" => Ok(normalized),
        _ => Err(Error::validation(
            "severity must be one of critical/high/normal/low",
        )),
    }
}

pub(super) fn normalize_event_status(raw: &str) -> Result<String, Error> {
    const MAX_STATUS_LEN: usize = 24;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("status must not be empty"));
    }
    if trimmed.chars().count() > MAX_STATUS_LEN {
        return Err(Error::validation("status is too long"));
    }
    Ok(trimmed.to_string())
}

pub(super) fn normalize_event_message(raw: &str) -> Result<String, Error> {
    const MAX_MESSAGE_LEN: usize = 512;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::validation("message must not be empty"));
    }
    if trimmed.chars().count() > MAX_MESSAGE_LEN {
        return Err(Error::validation("message is too long"));
    }
    Ok(trimmed.to_string())
}

impl EventRouteAction {
    pub(super) fn validate_temporal_fields(
        self,
        started_at: Option<i64>,
        ended_at: Option<i64>,
    ) -> Result<(), Error> {
        match self {
            EventRouteAction::Create => {
                if ended_at.is_some() {
                    return Err(Error::validation(
                        "ended_at is only allowed on /event/close",
                    ));
                }
            }
            EventRouteAction::Update => {
                if started_at.is_some() || ended_at.is_some() {
                    return Err(Error::validation(
                        "started_at and ended_at are not allowed on /event/update",
                    ));
                }
            }
            EventRouteAction::Close => {
                if started_at.is_some() {
                    return Err(Error::validation(
                        "started_at is only allowed on /event/create",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_required_fields(
        self,
        title: Option<&str>,
        status: &Option<String>,
        message: &Option<String>,
        severity: &Option<String>,
    ) -> Result<(), Error> {
        match self {
            EventRouteAction::Create => {
                if title.is_none() || status.is_none() || message.is_none() || severity.is_none() {
                    return Err(Error::validation(
                        "title, status, message and severity are required on /event/create",
                    ));
                }
            }
            EventRouteAction::Update | EventRouteAction::Close => {
                if status.is_none() || message.is_none() || severity.is_none() {
                    return Err(Error::validation(
                        "status, message and severity are required on /event/update and /event/close",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn resolve_started_at(
        self,
        incoming: Option<i64>,
        existing: Option<i64>,
        event_time: i64,
    ) -> Option<i64> {
        match self {
            EventRouteAction::Create => incoming.or(existing).or(Some(event_time)),
            EventRouteAction::Update | EventRouteAction::Close => existing,
        }
    }

    pub(super) fn resolve_ended_at(
        self,
        incoming: Option<i64>,
        existing: Option<i64>,
        event_time: i64,
    ) -> Option<i64> {
        match self {
            EventRouteAction::Close => incoming.or(existing).or(Some(event_time)),
            EventRouteAction::Create | EventRouteAction::Update => existing,
        }
    }

    pub(super) fn target_state(self) -> EventState {
        match self {
            EventRouteAction::Create | EventRouteAction::Update => EventState::Ongoing,
            EventRouteAction::Close => EventState::Closed,
        }
    }
}

impl EventProfile {
    pub(super) fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.description.is_none()
            && self.status.is_none()
            && self.message.is_none()
            && self.severity.is_none()
            && self.tags.is_empty()
            && self.images.is_empty()
            && self.started_at.is_none()
            && self.ended_at.is_none()
    }
}
