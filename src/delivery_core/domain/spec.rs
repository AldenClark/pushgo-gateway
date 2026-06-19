#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainModelKind {
    Message,
    Event,
    Thing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainActionKind {
    Send,
    Create,
    Update,
    Close,
    Archive,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntityIdKind {
    MessageId,
    EventId,
    ThingId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActionSpec {
    pub(crate) model: DomainModelKind,
    pub(crate) action: DomainActionKind,
    pub(crate) required_fields: &'static [&'static str],
    pub(crate) forbidden_fields: &'static [&'static str],
    pub(crate) generated_id: Option<EntityIdKind>,
    pub(crate) required_existing_id: Option<EntityIdKind>,
    pub(crate) required_time_field: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_core::domain::{
        event::EventCommandKind, message::MessageSend, thing::ThingCommandKind,
    };

    #[test]
    fn action_specs_cover_current_domain_model_contracts() {
        let message = MessageSend::SPEC;
        assert_eq!(message.model, DomainModelKind::Message);
        assert_eq!(message.action, DomainActionKind::Send);
        assert_contains(message.required_fields, "title");
        assert_contains(message.forbidden_fields, "message_id");
        assert_eq!(message.generated_id, Some(EntityIdKind::MessageId));
        assert_eq!(message.required_existing_id, None);

        let event_specs = [
            EventCommandKind::Create.spec(),
            EventCommandKind::Update.spec(),
            EventCommandKind::Close.spec(),
        ];
        assert_eq!(event_specs.len(), 3);
        assert_eq!(event_specs[0].generated_id, Some(EntityIdKind::EventId));
        assert_contains(event_specs[0].forbidden_fields, "event_id");
        for spec in event_specs {
            assert_eq!(spec.model, DomainModelKind::Event);
            assert_eq!(spec.required_time_field, Some("event_time"));
            assert_contains(spec.required_fields, "event_time");
            if spec.action != DomainActionKind::Create {
                assert_eq!(spec.required_existing_id, Some(EntityIdKind::EventId));
                assert_contains(spec.required_fields, "event_id");
            }
        }

        let thing_specs = [
            ThingCommandKind::Create.spec(),
            ThingCommandKind::Update.spec(),
            ThingCommandKind::Archive.spec(),
            ThingCommandKind::Delete.spec(),
        ];
        assert_eq!(thing_specs.len(), 4);
        assert_eq!(thing_specs[0].generated_id, Some(EntityIdKind::ThingId));
        assert_contains(thing_specs[0].forbidden_fields, "thing_id");
        for spec in thing_specs {
            assert_eq!(spec.model, DomainModelKind::Thing);
            assert_eq!(spec.required_time_field, Some("observed_at"));
            assert_contains(spec.required_fields, "observed_at");
            if spec.action != DomainActionKind::Create {
                assert_eq!(spec.required_existing_id, Some(EntityIdKind::ThingId));
                assert_contains(spec.required_fields, "thing_id");
            }
        }
    }

    fn assert_contains(values: &[&str], expected: &str) {
        assert!(
            values.contains(&expected),
            "{values:?} should contain {expected}"
        );
    }
}
