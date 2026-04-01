use std::sync::Arc;

use hashbrown::HashMap;
use serde::Serialize;

use crate::{private::protocol::PrivatePayloadEnvelope, util::build_wakeup_data};

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
        ProviderWakeupData(Arc::new(build_wakeup_data(&self.data)))
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
            "private_mode",
            "private_wakeup",
            "private_wakeup_handled",
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

    pub(crate) fn default_notification_body(self) -> &'static str {
        match self.0 {
            "event" => "Event updated.",
            "thing" => "Object updated.",
            _ => "You received a new message.",
        }
    }

    pub(crate) fn wakeup_fallback_title(self, message_title: Option<&str>) -> String {
        if self.0 == "message"
            && let Some(trimmed_title) = message_title
                .map(str::trim)
                .filter(|value| !value.is_empty())
        {
            return trimmed_title.to_string();
        }
        "You have a new notification.".to_string()
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
