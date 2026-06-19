use hashbrown::HashMap;
use serde_json::{Map as JsonMap, Value};

use crate::{
    delivery_core::{error::CoreError, payload::EntityKind, store::idempotency::IdempotencyStore},
    value::{EntityId, MetadataEntries, NormalizedImageUrls, NormalizedTags, OpId, OptionalText},
};

use super::{
    common::DomainAction,
    ids::{ResolvedSemanticId, SemanticScope},
    projection::{
        AlertHint, DomainDeliveryPolicy, DomainPayloadProjection, EntityRef, NormalizedEnvelope,
    },
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
pub(crate) enum MessageCommand {
    Send(MessageSend),
}

#[derive(Debug, Clone)]
pub(crate) struct MessageSend {
    pub(crate) input: MessageInput,
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedMessageCommand {
    pub(crate) message_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) projection: DomainPayloadProjection,
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

    pub(crate) async fn normalize(
        self,
        idempotency: &(dyn IdempotencyStore + Send + Sync),
        channel_id: [u8; 16],
        channel_id_text: String,
        now_millis: i64,
    ) -> Result<NormalizedEnvelope<NormalizedMessageCommand>, CoreError> {
        self.input.validate()?;
        let thing_id = self
            .input
            .thing_id
            .as_deref()
            .map(|raw| EntityId::parse(raw, "thing_id").map(EntityId::into_inner))
            .transpose()?;
        let occurred_at = if thing_id.is_some() {
            self.input.occurred_at.ok_or_else(|| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "message.route_rejected",
                    channel_id = %(crate::util::redact_text(channel_id_text.as_str())),
                    reason = %("occurred_at_required_for_thing_scoped_message")
                );
                CoreError::validation_code(
                    "occurred_at is required when message is scoped to thing_id",
                    "occurred_at_required_for_thing_scoped_message",
                )
            })?
        } else {
            self.input.occurred_at.unwrap_or(now_millis)
        };
        let op_id = OpId::resolve(self.input.op_id.as_deref())?;
        let message_id = ResolvedSemanticId::resolve_create(
            idempotency,
            SemanticScope::semantic_create_key(
                &channel_id_text,
                "message",
                thing_id.as_deref(),
                &op_id,
            )
            .as_str(),
        )
        .await?
        .semantic_id;
        let projection = self.project_payload(message_id.clone(), thing_id.clone())?;
        Ok(NormalizedEnvelope {
            channel_id,
            channel_id_text,
            op_id: op_id.into_inner(),
            occurred_at,
            action: DomainAction::Send,
            command: NormalizedMessageCommand {
                message_id,
                thing_id,
                projection,
            },
        })
    }

    fn project_payload(
        &self,
        message_id: String,
        thing_id: Option<String>,
    ) -> Result<DomainPayloadProjection, CoreError> {
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
        extra_fields.insert("message_id".to_string(), message_id.clone());
        if !normalized_tags.is_empty() {
            let encoded = serde_json::to_string(&normalized_tags).map_err(|_| {
                CoreError::validation_code("tags format is invalid", "tags_format_invalid")
            })?;
            extra_fields.insert("tags".to_string(), encoded);
        }
        if let Some(thing_id) = thing_id.clone() {
            extra_fields.insert("thing_id".to_string(), thing_id);
        }
        Ok(DomainPayloadProjection {
            entity: EntityRef::Message {
                message_id,
                thing_id,
            },
            alert: AlertHint {
                title: Some(self.input.title.clone()),
                body: normalized_body,
                severity: self.input.severity.clone(),
                ttl: self.input.ttl,
            },
            custom_data,
            extra_fields,
            delivery_policy: DomainDeliveryPolicy::for_model_action(
                EntityKind::Message,
                DomainAction::Send,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use serde_json::Map as JsonMap;

    use super::*;
    use crate::storage::{OpDedupeReservation, SemanticIdReservation, StoreResult};

    struct FakeIdempotencyStore;

    #[async_trait]
    impl IdempotencyStore for FakeIdempotencyStore {
        async fn reserve_semantic_id(
            &self,
            _key: &str,
            semantic_id: &str,
            _created_at: i64,
        ) -> StoreResult<SemanticIdReservation> {
            Ok(SemanticIdReservation::Existing {
                semantic_id: semantic_id.to_string(),
            })
        }

        async fn reserve_op_pending(
            &self,
            _key: &str,
            _delivery_id: &str,
            _created_at: i64,
        ) -> StoreResult<OpDedupeReservation> {
            unreachable!("message normalization should not reserve op dedupe")
        }

        async fn mark_op_sent(&self, _key: &str, _delivery_id: &str) -> StoreResult<bool> {
            unreachable!("message normalization should not mark op dedupe")
        }

        async fn clear_op_pending(&self, _key: &str, _delivery_id: &str) -> StoreResult<()> {
            unreachable!("message normalization should not clear op dedupe")
        }
    }

    #[tokio::test]
    async fn message_without_occurred_at_uses_submit_clock() {
        let normalized = MessageSend::new(MessageInput {
            op_id: Some("clock-op".to_string()),
            thing_id: None,
            occurred_at: None,
            title: "clocked".to_string(),
            body: None,
            severity: None,
            ttl: None,
            url: None,
            images: Vec::new(),
            ciphertext: None,
            tags: Vec::new(),
            metadata: JsonMap::new(),
        })
        .normalize(
            &FakeIdempotencyStore,
            [7; 16],
            "channel-clock".to_string(),
            1_725_000_123_456,
        )
        .await
        .expect("message should normalize");

        assert_eq!(normalized.occurred_at, 1_725_000_123_456);
    }
}
