use hashbrown::HashMap;
use serde_json::{Map as JsonMap, Value};

use crate::{
    delivery_core::error::CoreError,
    value::{EntityId, MetadataEntries, NormalizedImageUrls, NormalizedTags, OpId, OptionalText},
};

use super::{
    projection::AlertHint,
    spec::{ActionSpec, DomainActionKind, DomainModelKind, EntityIdKind},
};

#[derive(Debug, Clone)]
pub(crate) struct MessageInput {
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: Option<String>,
    pub(crate) occurred_at: Option<i64>,
    pub(crate) title: String,
    pub(crate) body: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) ttl: Option<i64>,
    pub(crate) url: Option<String>,
    pub(crate) images: Vec<String>,
    pub(crate) ciphertext: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) metadata: JsonMap<String, Value>,
}

#[derive(Debug, Clone)]
pub(crate) struct MessageSend {
    pub(crate) input: MessageInput,
}

/// Pure ordinary input preparation. Identity allocation belongs to the
/// ordinary ledger transaction, so preparing a message never writes a second
/// semantic-id or sender-status record.
#[derive(Debug, Clone)]
pub(crate) struct PreparedMessage {
    pub(crate) op_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) occurred_at: i64,
    pub(crate) fingerprint_occurred_at: Option<i64>,
    pub(crate) ttl: Option<i64>,
    pub(crate) fields: std::collections::BTreeMap<String, String>,
    pub(crate) fingerprint: String,
}

impl MessageInput {
    pub(crate) fn validate(&self) -> Result<(), CoreError> {
        if let Some(op_id) = self.op_id.as_deref() {
            OpId::parse(op_id)?;
        }
        if self.title.trim().is_empty() {
            return Err(CoreError::validation_code(
                "title must not be empty",
                "title_required",
            ));
        }
        MetadataEntries::new(&self.metadata).validate()?;
        Ok(())
    }
}

type ProjectedMessageContent = (AlertHint, HashMap<String, String>, HashMap<String, String>);

impl MessageSend {
    pub(crate) const SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Message,
        action: DomainActionKind::Send,
        required_fields: &["title"],
        forbidden_fields: &["message_id"],
        generated_id: Some(EntityIdKind::Message),
        required_existing_id: None,
        required_time_field: None,
    };

    pub(crate) fn spec(&self) -> ActionSpec {
        Self::SPEC
    }

    pub(crate) fn new(input: MessageInput) -> Self {
        Self { input }
    }

    pub(crate) fn prepare(self, now_millis: i64) -> Result<PreparedMessage, CoreError> {
        self.input.validate()?;
        let thing_id = self
            .input
            .thing_id
            .as_deref()
            .map(|raw| EntityId::parse(raw, "thing_id").map(EntityId::into_inner))
            .transpose()?;
        let occurred_at = match (&thing_id, self.input.occurred_at) {
            (Some(_), None) => {
                return Err(CoreError::validation_code(
                    "occurred_at is required when message is scoped to thing_id",
                    "occurred_at_required_for_thing_scoped_message",
                ));
            }
            (_, value) => value.unwrap_or(now_millis),
        };
        let op_id = self
            .input
            .op_id
            .as_deref()
            .map(OpId::parse)
            .transpose()?
            .unwrap_or_else(|| OpId::generate(now_millis))
            .into_inner();
        let (alert, custom_data, extra_fields) = self.project_content(thing_id.as_deref())?;
        let mut fields = std::collections::BTreeMap::new();
        fields.extend(custom_data);
        fields.extend(extra_fields);
        fields.insert(
            "title".into(),
            alert.title.as_deref().unwrap_or_default().trim().into(),
        );
        if let Some(body) = alert.body {
            fields.insert("body".into(), body);
        }
        fields.insert(
            "severity".into(),
            crate::value::NotificationSeverity::normalize(alert.severity.clone())
                .as_str()
                .into(),
        );
        let mut fingerprint_fields = fields.clone();
        // Preserve the product conflict rule: severity is fingerprinted before
        // provider normalization; absent occurred_at is not the changing clock.
        fingerprint_fields.insert("severity".into(), alert.severity.unwrap_or_default());
        let fingerprint = blake3::hash(
            &serde_json::to_vec(&(fingerprint_fields, self.input.occurred_at, self.input.ttl))
                .map_err(|error| CoreError::internal(error.to_string()))?,
        )
        .to_hex()
        .to_string();
        Ok(PreparedMessage {
            op_id,
            thing_id,
            occurred_at,
            fingerprint_occurred_at: self.input.occurred_at,
            ttl: self.input.ttl,
            fields,
            fingerprint,
        })
    }

    fn project_content(
        &self,
        thing_id: Option<&str>,
    ) -> Result<ProjectedMessageContent, CoreError> {
        let normalized_body = OptionalText::normalize_owned(self.input.body.clone());
        let normalized_url = OptionalText::normalize_owned(self.input.url.clone());
        let normalized_images =
            NormalizedImageUrls::parse(&self.input.images, "images")?.into_inner();
        let mut custom_data = HashMap::with_capacity(4);
        if let Some(url) = normalized_url {
            custom_data.insert("url".to_string(), url);
        }
        if !normalized_images.is_empty() {
            let encoded = serde_json::to_string(&normalized_images).map_err(|_| {
                CoreError::validation_code("images format is invalid", "images_format_invalid")
            })?;
            custom_data.insert("images".to_string(), encoded);
        }
        if let Some(ciphertext) = OptionalText::normalize_owned(self.input.ciphertext.clone()) {
            custom_data.insert("ciphertext".to_string(), ciphertext);
        }
        let normalized_tags = NormalizedTags::parse(&self.input.tags, "tags")?.into_inner();
        if !self.input.metadata.is_empty() {
            let encoded = MetadataEntries::new(&self.input.metadata).encode()?;
            custom_data.insert("metadata".to_string(), encoded);
        }
        let mut extra_fields = HashMap::with_capacity(3);
        if !normalized_tags.is_empty() {
            let encoded = serde_json::to_string(&normalized_tags).map_err(|_| {
                CoreError::validation_code("tags format is invalid", "tags_format_invalid")
            })?;
            extra_fields.insert("tags".to_string(), encoded);
        }
        if let Some(thing_id) = thing_id {
            extra_fields.insert("thing_id".to_string(), thing_id.to_owned());
        }
        Ok((
            AlertHint {
                title: Some(self.input.title.clone()),
                body: normalized_body,
                severity: self.input.severity.clone(),
                ttl: self.input.ttl,
            },
            custom_data,
            extra_fields,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> MessageInput {
        MessageInput {
            op_id: Some("pure-op".into()),
            thing_id: None,
            occurred_at: None,
            title: "  title  ".into(),
            body: Some(" body ".into()),
            severity: None,
            ttl: None,
            url: None,
            images: Vec::new(),
            ciphertext: None,
            tags: Vec::new(),
            metadata: JsonMap::new(),
        }
    }

    #[test]
    fn pure_message_preparation_uses_clock_without_allocating_identity() {
        let prepared = MessageSend::new(input())
            .prepare(1_725_000_123_456)
            .unwrap();
        assert_eq!(prepared.occurred_at, 1_725_000_123_456);
        assert_eq!(prepared.fingerprint_occurred_at, None);
        assert_eq!(
            prepared.fields.get("title").map(String::as_str),
            Some("title")
        );
        assert_eq!(
            prepared.fields.get("body").map(String::as_str),
            Some("body")
        );
        assert!(!prepared.fields.contains_key("message_id"));
        assert!(!prepared.fields.contains_key("delivery_id"));
    }

    #[test]
    fn thing_scoped_message_keeps_association_and_requires_occurred_at() {
        let mut command = input();
        command.thing_id = Some("thing-ordinary".into());
        assert!(matches!(
            MessageSend::new(command.clone()).prepare(10),
            Err(CoreError::Validation {
                code: "occurred_at_required_for_thing_scoped_message",
                ..
            })
        ));
        command.occurred_at = Some(123);
        let prepared = MessageSend::new(command).prepare(999).unwrap();
        assert_eq!(prepared.thing_id.as_deref(), Some("thing-ordinary"));
        assert_eq!(prepared.occurred_at, 123);
        assert_eq!(
            prepared.fields.get("thing_id").map(String::as_str),
            Some("thing-ordinary")
        );
    }

    #[test]
    fn omitted_clock_is_not_part_of_duplicate_fingerprint() {
        let first = MessageSend::new(input()).prepare(10).unwrap();
        let retry = MessageSend::new(input()).prepare(999).unwrap();
        assert_eq!(first.fingerprint, retry.fingerprint);
        let mut changed = input();
        changed.thing_id = Some("different-scope".into());
        changed.occurred_at = Some(10);
        assert_ne!(
            first.fingerprint,
            MessageSend::new(changed).prepare(10).unwrap().fingerprint
        );
    }

    #[test]
    fn pure_preparation_preserves_absolute_ttl_including_elapsed_values() {
        let now = 1_725_000_000_000;
        for ttl in [0, -1, now - 1, now + 60_000, i64::MAX] {
            let mut command = input();
            command.ttl = Some(ttl);
            let prepared = MessageSend::new(command).prepare(now).unwrap();
            assert_eq!(prepared.ttl, Some(ttl));
            assert!(
                !prepared.fields.contains_key("ttl"),
                "the acceptance transaction freezes the final absolute expiry"
            );
        }
        let absent = MessageSend::new(input()).prepare(now).unwrap();
        let mut zero = input();
        zero.ttl = Some(0);
        assert_ne!(
            absent.fingerprint,
            MessageSend::new(zero).prepare(now).unwrap().fingerprint
        );
    }

    #[test]
    fn product_and_ordinary_generated_message_ids_share_the_accepted_wire_format() {
        for id in [
            crate::util::generate_hex_id_128(),
            crate::ordinary::types::generate_hex_id_128(),
        ] {
            assert_eq!(id.len(), 32);
            assert!(
                id.bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            );
            assert_eq!(EntityId::parse(&id, "message_id").unwrap().into_inner(), id);
        }
    }
}
