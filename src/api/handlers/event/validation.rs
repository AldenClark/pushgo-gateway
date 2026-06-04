use crate::{api::Error, storage::EventState};

use super::{EventCommandKind, EventProfile};

impl EventCommandKind {
    pub(super) fn validate_required_fields(
        self,
        title: Option<&str>,
        status: &Option<String>,
        message: &Option<String>,
        severity: &Option<String>,
    ) -> Result<(), Error> {
        match self {
            EventCommandKind::Create => {
                if title.is_none() || status.is_none() || message.is_none() || severity.is_none() {
                    return Err(Error::validation_code(
                        "title, status, message and severity are required on /event/create",
                        "event_create_required_fields_missing",
                    ));
                }
            }
            EventCommandKind::Update | EventCommandKind::Close => {}
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
            EventCommandKind::Create => incoming.or(existing).or(Some(event_time)),
            EventCommandKind::Update | EventCommandKind::Close => existing,
        }
    }

    pub(super) fn resolve_ended_at(
        self,
        incoming: Option<i64>,
        existing: Option<i64>,
        event_time: i64,
    ) -> Option<i64> {
        match self {
            EventCommandKind::Close => incoming.or(existing).or(Some(event_time)),
            EventCommandKind::Create | EventCommandKind::Update => existing,
        }
    }

    pub(super) fn state_patch(self) -> Option<EventState> {
        match self {
            EventCommandKind::Create => Some(EventState::Ongoing),
            EventCommandKind::Update => None,
            EventCommandKind::Close => Some(EventState::Closed),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_update_and_close_do_not_require_full_status_fields() {
        assert!(
            EventCommandKind::Update
                .validate_required_fields(None, &None, &None, &None)
                .is_ok()
        );
        assert!(
            EventCommandKind::Close
                .validate_required_fields(None, &None, &None, &None)
                .is_ok()
        );
    }

    #[test]
    fn event_update_does_not_patch_state() {
        assert_eq!(EventCommandKind::Update.state_patch(), None);
        assert_eq!(
            EventCommandKind::Create.state_patch(),
            Some(EventState::Ongoing)
        );
        assert_eq!(
            EventCommandKind::Close.state_patch(),
            Some(EventState::Closed)
        );
    }
}
