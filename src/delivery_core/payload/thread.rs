use hashbrown::HashMap;

use crate::value::{EntityKind, OptionalText};

pub(crate) struct AppleThreadId(pub(crate) String);

pub(crate) struct AppleThreadIdResolver;

impl AppleThreadIdResolver {
    pub(crate) fn resolve(
        channel_id: &str,
        entity_kind: EntityKind,
        data: &HashMap<String, String>,
    ) -> AppleThreadId {
        let mut parts = vec![entity_kind.as_str().to_string()];
        let trimmed_channel = channel_id.trim();
        if !trimmed_channel.is_empty() {
            parts.push(format!("channel={trimmed_channel}"));
        }
        if entity_kind.includes_event_id()
            && let Some(event_id) = data
                .get("event_id")
                .map(String::as_str)
                .and_then(OptionalText::normalize_value)
        {
            parts.push(format!("event={event_id}"));
        }
        if entity_kind.includes_thing_id()
            && let Some(thing_id) = data
                .get("thing_id")
                .map(String::as_str)
                .and_then(OptionalText::normalize_value)
        {
            parts.push(format!("thing={thing_id}"));
        }
        AppleThreadId(parts.join("|"))
    }
}

impl AppleThreadId {
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}
