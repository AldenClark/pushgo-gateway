use hashbrown::HashMap;
use serde::Deserialize;

use crate::value::{EntityKind, OptionalText};

#[derive(Debug, Default, Deserialize)]
struct WatchProfile {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

struct WatchLightPayload<'a> {
    payload: &'a HashMap<String, String>,
}

impl WatchProfile {
    fn from_payload(payload: &HashMap<String, String>, is_thing: bool) -> Self {
        let image = if is_thing {
            Self::field(payload.get("image")).or_else(|| Self::field(payload.get("primary_image")))
        } else {
            Self::field(payload.get("image"))
        };
        Self {
            title: Self::field(payload.get("title")),
            description: Self::field(payload.get("description")),
            image,
            severity: Self::field(payload.get("severity")),
        }
    }

    fn field(value: Option<&String>) -> Option<String> {
        value
            .map(String::as_str)
            .and_then(OptionalText::normalize_value)
    }
}

impl<'a> WatchLightPayload<'a> {
    fn new(payload: &'a HashMap<String, String>) -> Self {
        Self { payload }
    }

    fn quantize(&self) -> HashMap<String, String> {
        let mut output = match self.kind() {
            EntityKind::Event => self.event_payload(),
            EntityKind::Thing => self.thing_payload(),
            EntityKind::Message => self.message_payload(),
        };

        if output.is_empty() {
            return output;
        }

        self.extend_common_fields(&mut output);
        output
    }

    fn kind(&self) -> EntityKind {
        EntityKind::detect(self.field("entity_type").as_deref())
    }

    fn field(&self, key: &str) -> Option<String> {
        self.payload
            .get(key)
            .map(String::as_str)
            .and_then(OptionalText::normalize_value)
    }

    fn insert_if_present(
        output: &mut HashMap<String, String>,
        key: &'static str,
        value: Option<String>,
    ) {
        if let Some(value) = value {
            output.insert(key.to_string(), value);
        }
    }

    fn extend_common_fields(&self, output: &mut HashMap<String, String>) {
        for key in [
            "channel_id",
            "delivery_id",
            "sent_at",
            "occurred_at",
            "severity",
            "entity_type",
            "entity_id",
        ] {
            if let Some(value) = self.field(key) {
                output.insert(key.to_string(), value);
            }
        }
    }

    fn event_payload(&self) -> HashMap<String, String> {
        let profile = WatchProfile::from_payload(self.payload, false);
        let Some(event_id) = self.field("event_id").or_else(|| self.field("entity_id")) else {
            return HashMap::new();
        };
        let mut output = HashMap::with_capacity(8);
        output.insert("watch_light_kind".to_string(), "event".to_string());
        output.insert("event_id".to_string(), event_id.clone());
        output.insert(
            "title".to_string(),
            profile
                .title
                .or_else(|| self.field("title"))
                .unwrap_or(event_id),
        );
        Self::insert_if_present(
            &mut output,
            "body",
            profile.description.or_else(|| self.field("body")),
        );
        Self::insert_if_present(&mut output, "event_state", self.field("event_state"));
        Self::insert_if_present(
            &mut output,
            "image",
            profile.image.or_else(|| self.field("image")),
        );
        Self::insert_if_present(
            &mut output,
            "severity",
            profile.severity.or_else(|| self.field("severity")),
        );
        output
    }

    fn thing_payload(&self) -> HashMap<String, String> {
        let profile = WatchProfile::from_payload(self.payload, true);
        let Some(thing_id) = self.field("thing_id").or_else(|| self.field("entity_id")) else {
            return HashMap::new();
        };
        let mut output = HashMap::with_capacity(8);
        output.insert("watch_light_kind".to_string(), "thing".to_string());
        output.insert("thing_id".to_string(), thing_id.clone());
        output.insert(
            "title".to_string(),
            profile
                .title
                .or_else(|| self.field("title"))
                .unwrap_or(thing_id),
        );
        Self::insert_if_present(
            &mut output,
            "body",
            profile.description.or_else(|| self.field("body")),
        );
        Self::insert_if_present(&mut output, "attrs", self.field("attrs"));
        Self::insert_if_present(
            &mut output,
            "image",
            profile
                .image
                .or_else(|| self.field("image"))
                .or_else(|| self.field("primary_image")),
        );
        Self::insert_if_present(
            &mut output,
            "observed_at",
            self.field("observed_at").or_else(|| self.field("sent_at")),
        );
        output
    }

    fn message_payload(&self) -> HashMap<String, String> {
        let Some(message_id) = self.field("message_id") else {
            return HashMap::new();
        };
        let mut output = HashMap::with_capacity(6);
        output.insert("watch_light_kind".to_string(), "message".to_string());
        output.insert("message_id".to_string(), message_id.clone());
        output.insert(
            "title".to_string(),
            self.field("title").unwrap_or(message_id),
        );
        Self::insert_if_present(&mut output, "body", self.field("body"));
        Self::insert_if_present(&mut output, "image", self.field("image"));
        Self::insert_if_present(&mut output, "url", self.field("url"));
        output
    }
}

pub(crate) fn quantize_watch_payload(payload: &HashMap<String, String>) -> HashMap<String, String> {
    WatchLightPayload::new(payload).quantize()
}

#[cfg(test)]
mod tests {
    use super::quantize_watch_payload;
    use hashbrown::HashMap;

    #[test]
    fn event_payload_prefers_profile_fields_and_common_metadata() {
        let mut payload = HashMap::new();
        payload.insert("entity_type".to_string(), "event".to_string());
        payload.insert("event_id".to_string(), "evt-1".to_string());
        payload.insert("title".to_string(), "Alarm".to_string());
        payload.insert("description".to_string(), "Door open".to_string());
        payload.insert("severity".to_string(), "high".to_string());
        payload.insert("channel_id".to_string(), "ch-1".to_string());
        let output = quantize_watch_payload(&payload);
        assert_eq!(
            output.get("watch_light_kind").map(String::as_str),
            Some("event")
        );
        assert_eq!(output.get("title").map(String::as_str), Some("Alarm"));
        assert_eq!(output.get("body").map(String::as_str), Some("Door open"));
        assert_eq!(output.get("severity").map(String::as_str), Some("high"));
        assert_eq!(output.get("channel_id").map(String::as_str), Some("ch-1"));
    }

    #[test]
    fn thing_payload_falls_back_to_primary_image() {
        let mut payload = HashMap::new();
        payload.insert("entity_type".to_string(), "thing".to_string());
        payload.insert("thing_id".to_string(), "thing-1".to_string());
        payload.insert("primary_image".to_string(), "https://img".to_string());
        let output = quantize_watch_payload(&payload);
        assert_eq!(
            output.get("watch_light_kind").map(String::as_str),
            Some("thing")
        );
        assert_eq!(output.get("image").map(String::as_str), Some("https://img"));
    }

    #[test]
    fn message_payload_requires_message_id() {
        let output = quantize_watch_payload(&HashMap::new());
        assert!(output.is_empty());
    }
}
