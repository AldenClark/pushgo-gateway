use std::sync::Arc;

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{private::protocol::PrivatePayloadEnvelope, util::build_provider_wakeup_data};

pub(crate) const PAYLOAD_VERSION_NUMERIC: u8 = PrivatePayloadEnvelope::CURRENT_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadSeverity {
    Critical,
    High,
    Normal,
    Low,
}

pub(crate) struct StandardFields<'a> {
    pub channel_id: &'a str,
    pub title: Option<&'a str>,
    pub body: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub schema_version: &'a str,
    pub payload_version: &'a str,
    pub op_id: &'a str,
    pub delivery_id: &'a str,
    pub ingested_at: i64,
    pub occurred_at: i64,
    pub sent_at: i64,
    pub ttl: Option<i64>,
    pub entity_type: &'a str,
    pub entity_id: &'a str,
}

pub(crate) struct CustomPayloadData {
    data: HashMap<String, String>,
}

pub(crate) struct PreparedCustomPayload {
    pub(crate) custom_data: Arc<HashMap<String, String>>,
    pub(crate) apple_thread_id: AppleThreadId,
    pub(crate) wakeup_data: ProviderWakeupData,
    pub(crate) private_payload: EncodedPrivatePayload,
}

pub(crate) struct OptionalText;

#[derive(Clone, Copy)]
pub(crate) struct EntityKind<'a>(&'a str);

pub(crate) struct AppleThreadId(pub(crate) String);

pub(crate) struct ProviderWakeupData(pub(crate) Arc<HashMap<String, String>>);

pub(crate) struct EncodedPrivatePayload(pub(crate) Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderNotificationText {
    pub(crate) title: Option<String>,
    pub(crate) body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProviderProfileSnapshot {
    title: Option<String>,
    description: Option<String>,
    message: Option<String>,
}

impl PayloadSeverity {
    pub(crate) fn normalize(value: Option<String>) -> Self {
        match OptionalText::normalize_owned(value)
            .map(|level| level.to_ascii_lowercase())
            .as_deref()
        {
            Some("critical") => Self::Critical,
            Some("high") => Self::High,
            Some("low") => Self::Low,
            _ => Self::Normal,
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
            Self::Critical | Self::High => "HIGH",
            Self::Normal | Self::Low => "NORMAL",
        }
    }
}

impl StandardFields<'_> {
    pub(crate) fn apply_to(self, data: &mut HashMap<String, String>) {
        data.insert("channel_id".to_string(), self.channel_id.to_string());
        if let Some(value) = self.title.map(str::trim).filter(|text| !text.is_empty()) {
            data.insert("title".to_string(), value.to_string());
        }
        if let Some(value) = self.body.map(str::trim).filter(|text| !text.is_empty()) {
            data.insert("body".to_string(), value.to_string());
        }
        if let Some(value) = self.severity.map(str::trim).filter(|text| !text.is_empty()) {
            data.insert("severity".to_string(), value.to_string());
        }
        data.insert(
            "schema_version".to_string(),
            self.schema_version.to_string(),
        );
        data.insert(
            "payload_version".to_string(),
            self.payload_version.to_string(),
        );
        data.insert("op_id".to_string(), self.op_id.to_string());
        data.insert("delivery_id".to_string(), self.delivery_id.to_string());
        data.insert("ingested_at".to_string(), self.ingested_at.to_string());
        data.insert("occurred_at".to_string(), self.occurred_at.to_string());
        data.insert("sent_at".to_string(), self.sent_at.to_string());
        data.insert("entity_type".to_string(), self.entity_type.to_string());
        data.insert("entity_id".to_string(), self.entity_id.to_string());
        if let Some(ttl) = self.ttl {
            data.insert("ttl".to_string(), ttl.to_string());
        }
    }
}

impl CustomPayloadData {
    pub(crate) fn new(mut data: HashMap<String, String>) -> Self {
        Self::sanitize(&mut data);
        Self { data }
    }

    pub(crate) fn apply_standard_fields(&mut self, fields: StandardFields<'_>) {
        fields.apply_to(&mut self.data);
    }

    pub(crate) fn insert_extra_fields(&mut self, extra_fields: HashMap<String, String>) {
        for (key, value) in extra_fields {
            self.data.insert(key, value);
        }
    }

    pub(crate) fn apply_gateway_base_url(&mut self, base_url: Option<&str>) {
        let normalized = base_url
            .map(str::trim)
            .map(|value| value.trim_end_matches('/'))
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        if let Some(value) = normalized {
            self.data.insert("base_url".to_string(), value);
        }
    }

    pub(crate) fn resolve_notification_text(
        &self,
        entity_kind: EntityKind<'_>,
        explicit_title: Option<&str>,
        explicit_body: Option<&str>,
    ) -> ProviderNotificationText {
        entity_kind.resolve_notification_text(explicit_title, explicit_body, &self.data)
    }

    pub(crate) fn ensure_notification_title(&mut self, title: Option<&str>) {
        let normalized = title
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        if let Some(title) = normalized {
            self.data.entry("title".to_string()).or_insert(title);
        }
    }

    fn apple_thread_id(&self, channel_id: &str, entity_kind: EntityKind<'_>) -> AppleThreadId {
        let mut parts = vec![entity_kind.apple_thread_prefix().to_string()];
        let trimmed_channel = channel_id.trim();
        if !trimmed_channel.is_empty() {
            parts.push(format!("channel={trimmed_channel}"));
        }
        if entity_kind.includes_event_id()
            && let Some(event_id) = self
                .data
                .get("event_id")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        {
            parts.push(format!("event={event_id}"));
        }
        if entity_kind.includes_thing_id()
            && let Some(thing_id) = self
                .data
                .get("thing_id")
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        {
            parts.push(format!("thing={thing_id}"));
        }
        AppleThreadId(parts.join("|"))
    }

    fn wakeup_data(&self) -> ProviderWakeupData {
        ProviderWakeupData(Arc::new(build_provider_wakeup_data(&self.data)))
    }

    fn encode_private_payload(&self) -> Result<EncodedPrivatePayload, postcard::Error> {
        #[derive(Serialize)]
        struct BorrowedPrivatePayloadEnvelope<'a> {
            payload_version: u8,
            data: &'a HashMap<String, String>,
        }

        postcard::to_allocvec(&BorrowedPrivatePayloadEnvelope {
            payload_version: PAYLOAD_VERSION_NUMERIC,
            data: &self.data,
        })
        .map(EncodedPrivatePayload)
    }

    pub(crate) fn into_shared(self) -> Arc<HashMap<String, String>> {
        Arc::new(self.data)
    }

    pub(crate) fn prepare_dispatch(
        self,
        channel_id: &str,
        entity_kind: EntityKind<'_>,
    ) -> Result<PreparedCustomPayload, postcard::Error> {
        let apple_thread_id = self.apple_thread_id(channel_id, entity_kind);
        let wakeup_data = self.wakeup_data();
        let private_payload = self.encode_private_payload()?;
        let custom_data = self.into_shared();
        Ok(PreparedCustomPayload {
            custom_data,
            apple_thread_id,
            wakeup_data,
            private_payload,
        })
    }

    fn sanitize(data: &mut HashMap<String, String>) {
        for key in [
            "title",
            "body",
            "channel_id",
            "level",
            "schema_version",
            "payload_version",
            "op_id",
            "delivery_id",
            "ingested_at",
            "message_id",
            "occurred_at",
            "sent_at",
            "ttl",
            "entity_type",
            "entity_id",
            "event_id",
            "event_state",
            "event_time",
            "event_title",
            "event_description",
            "event_profile_json",
            "event_attrs_json",
            "event_unset_json",
            "severity",
            "tags",
            "attachments",
            "started_at",
            "ended_at",
            "thing_id",
            "thing_profile_json",
            "thing_attrs_json",
            "thing_unset_json",
            "image",
            "primary_image",
            "attachments",
            "created_at",
            "state",
            "deleted_at",
            "external_ids",
            "location_type",
            "location_value",
            "observed_at",
            "notify_user",
            "local_notify",
            "provider_mode",
            "provider_wakeup",
            "provider_wakeup_handled",
            "_skip_persist",
        ] {
            data.remove(key);
        }
    }
}

impl OptionalText {
    pub(crate) fn normalize_owned(value: Option<String>) -> Option<String> {
        value.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
    }
}

impl<'a> EntityKind<'a> {
    pub(crate) fn new(raw: &'a str) -> Self {
        Self(raw)
    }

    pub(crate) fn resolve_notification_text(
        self,
        explicit_title: Option<&str>,
        explicit_body: Option<&str>,
        payload: &HashMap<String, String>,
    ) -> ProviderNotificationText {
        match self.apple_thread_prefix() {
            "event" => ProviderNotificationText {
                title: normalize_optional_text(explicit_title).or_else(|| {
                    profile_snapshot(payload, "event_profile_json")
                        .and_then(|profile| normalize_optional_string(profile.title))
                        .or_else(|| map_text(payload, "event_title"))
                        .or_else(|| {
                            map_text(payload, "event_id")
                                .or_else(|| map_text(payload, "entity_id"))
                                .map(|id| format!("Event {id}"))
                        })
                }),
                body: normalize_optional_text(explicit_body).or_else(|| {
                    profile_snapshot(payload, "event_profile_json")
                        .and_then(|profile| {
                            normalize_optional_string(profile.message)
                                .or_else(|| normalize_optional_string(profile.description))
                        })
                        .or_else(|| default_event_body(payload))
                }),
            },
            "thing" => ProviderNotificationText {
                title: normalize_optional_text(explicit_title).or_else(|| {
                    thing_name_from_attrs(payload)
                        .or_else(|| {
                            profile_snapshot(payload, "thing_profile_json")
                                .and_then(|profile| normalize_optional_string(profile.title))
                        })
                        .or_else(|| {
                            map_text(payload, "thing_id")
                                .or_else(|| map_text(payload, "entity_id"))
                                .map(|id| format!("Object {id}"))
                        })
                }),
                body: normalize_optional_text(explicit_body).or_else(|| {
                    profile_snapshot(payload, "thing_profile_json")
                        .and_then(|profile| normalize_optional_string(profile.message))
                        .or_else(|| thing_attribute_update_body(payload))
                        .or_else(|| {
                            profile_snapshot(payload, "thing_profile_json")
                                .and_then(|profile| normalize_optional_string(profile.description))
                        })
                        .or_else(|| Some("Updated".to_string()))
                }),
            },
            _ => {
                let explicit_or_payload_body =
                    normalize_optional_text(explicit_body).or_else(|| map_text(payload, "body"));
                ProviderNotificationText {
                    title: normalize_optional_text(explicit_title)
                        .or_else(|| map_text(payload, "title"))
                        .or_else(|| map_text(payload, "url"))
                        .or_else(|| first_image_url(payload))
                        .or_else(|| {
                            map_text(payload, "message_id").map(|id| format!("Message {id}"))
                        })
                        .or_else(|| {
                            map_text(payload, "entity_id").map(|id| format!("Message {id}"))
                        }),
                    body: explicit_or_payload_body,
                }
            }
        }
    }

    fn apple_thread_prefix(self) -> &'static str {
        match self.0.trim().to_ascii_lowercase().as_str() {
            "event" => "event",
            "thing" => "thing",
            _ => "message",
        }
    }

    fn includes_event_id(self) -> bool {
        matches!(self.apple_thread_prefix(), "event" | "thing")
    }

    fn includes_thing_id(self) -> bool {
        self.apple_thread_prefix() == "thing"
    }
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn map_text(data: &HashMap<String, String>, key: &str) -> Option<String> {
    data.get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn profile_snapshot(data: &HashMap<String, String>, key: &str) -> Option<ProviderProfileSnapshot> {
    let raw = data.get(key)?;
    serde_json::from_str::<ProviderProfileSnapshot>(raw).ok()
}

fn default_event_body(data: &HashMap<String, String>) -> Option<String> {
    match map_text(data, "event_state")?.to_ascii_uppercase().as_str() {
        "OPEN" => Some("Opened".to_string()),
        "ONGOING" => Some("Ongoing".to_string()),
        "CLOSED" => Some("Closed".to_string()),
        _ => Some("Updated".to_string()),
    }
}

fn thing_name_from_attrs(data: &HashMap<String, String>) -> Option<String> {
    let raw = data.get("thing_attrs_json")?;
    let object = serde_json::from_str::<serde_json::Map<String, JsonValue>>(raw).ok()?;
    for key in ["name", "thing_name", "名称"] {
        if let Some(value) = object.get(key)
            && let Some(text) = json_scalar_text(value)
        {
            return Some(text);
        }
    }
    None
}

fn thing_attribute_update_body(data: &HashMap<String, String>) -> Option<String> {
    let raw = data.get("thing_attrs_json")?;
    let object = serde_json::from_str::<serde_json::Map<String, JsonValue>>(raw).ok()?;
    let mut pairs: Vec<(String, String)> = object
        .iter()
        .filter_map(|(key, value)| {
            let name = key.trim();
            if name.is_empty() {
                return None;
            }
            let text = json_scalar_text(value)?;
            Some((name.to_string(), text))
        })
        .collect();
    if pairs.is_empty() {
        return None;
    }
    pairs.sort_by(|lhs, rhs| {
        attribute_sort_priority(lhs.0.as_str())
            .cmp(&attribute_sort_priority(rhs.0.as_str()))
            .then_with(|| lhs.0.to_ascii_lowercase().cmp(&rhs.0.to_ascii_lowercase()))
    });
    let details = pairs
        .into_iter()
        .take(6)
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join(", ");
    (!details.is_empty()).then(|| format!("Attribute update || {details}"))
}

fn attribute_sort_priority(key: &str) -> i32 {
    let normalized = key.trim().to_ascii_lowercase();
    if normalized == "name" || normalized == "thing_name" || key.trim() == "名称" {
        0
    } else {
        1
    }
}

fn json_scalar_text(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(text) => normalize_optional_text(Some(text)),
        JsonValue::Number(number) => Some(number.to_string()),
        JsonValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn first_image_url(data: &HashMap<String, String>) -> Option<String> {
    let raw = data.get("images")?;
    let values = serde_json::from_str::<Vec<String>>(raw).ok()?;
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

impl AppleThreadId {
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl ProviderWakeupData {
    pub(crate) fn into_inner(self) -> Arc<HashMap<String, String>> {
        self.0
    }
}

impl EncodedPrivatePayload {
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    #[test]
    fn ensure_notification_title_promotes_derived_title_into_payload() {
        let body_text = "Body is present but should not be promoted as title";
        let mut payload = super::CustomPayloadData::new(HashMap::new());
        payload.apply_standard_fields(super::StandardFields {
            channel_id: "channel-1",
            title: None,
            body: Some(body_text),
            severity: None,
            schema_version: "1",
            payload_version: "1",
            op_id: "op-1",
            delivery_id: "delivery-1",
            ingested_at: 1,
            occurred_at: 1,
            sent_at: 1,
            ttl: None,
            entity_type: "message",
            entity_id: "message-1",
        });
        let title =
            payload.resolve_notification_text(super::EntityKind::new("message"), None, None);
        payload.ensure_notification_title(title.title.as_deref());
        let prepared = payload
            .prepare_dispatch("channel-1", super::EntityKind::new("message"))
            .expect("payload should encode");

        let wakeup = prepared.wakeup_data.into_inner();
        assert_ne!(
            wakeup.get("title").map(String::as_str),
            Some(body_text),
            "message wakeup title must not come from body preview"
        );
    }
}
