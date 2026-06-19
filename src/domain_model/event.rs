use hashbrown::HashMap;
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::{
    delivery_core::{error::CoreError, payload::EntityKind, store::idempotency::IdempotencyStore},
    value::{EntityId, MetadataEntries, OpId},
};

use super::{
    common::DomainAction,
    ids::{ResolvedSemanticId, SemanticScope},
    projection::{
        AlertHint, DomainDeliveryPolicy, DomainPayloadProjection, EntityRef, NormalizedEnvelope,
    },
    spec::{ActionSpec, DomainActionKind, DomainModelKind, EntityIdKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventCommandKind {
    Create,
    Update,
    Close,
}

#[derive(Debug, Clone)]
pub(crate) struct EventCreateCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: Option<String>,
    pub(crate) event_time: Option<i64>,
    pub(crate) started_at: Option<i64>,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) struct EventUpdateCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) event_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) event_time: Option<i64>,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) struct EventCloseCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) event_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) event_time: Option<i64>,
    pub(crate) ended_at: Option<i64>,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) enum EventCommand<P> {
    Create(EventCreateCommand<P>),
    Update(EventUpdateCommand<P>),
    Close(EventCloseCommand<P>),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EventPatch {
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) images: Option<Vec<String>>,
    pub(crate) ciphertext: Option<String>,
    pub(crate) attrs: Option<JsonMap<String, JsonValue>>,
    pub(crate) metadata: Option<JsonMap<String, JsonValue>>,
}

#[derive(Debug, Clone, Default)]
struct EventProfile {
    title: Option<String>,
    description: Option<String>,
    status: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    tags: Vec<String>,
    images: Vec<String>,
    started_at: Option<i64>,
    ended_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedEventCommand {
    pub(crate) event_id: String,
    pub(crate) thing_id: Option<String>,
    pub(crate) projection: DomainPayloadProjection,
}

impl<P> EventCommand<P> {
    pub(crate) fn kind(&self) -> EventCommandKind {
        match self {
            EventCommand::Create(_) => EventCommandKind::Create,
            EventCommand::Update(_) => EventCommandKind::Update,
            EventCommand::Close(_) => EventCommandKind::Close,
        }
    }

    pub(crate) fn action_name(&self) -> &'static str {
        self.kind().action_name()
    }

    pub(crate) fn op_id(&self) -> Option<&str> {
        match self {
            EventCommand::Create(command) => command.op_id.as_deref(),
            EventCommand::Update(command) => command.op_id.as_deref(),
            EventCommand::Close(command) => command.op_id.as_deref(),
        }
    }

    pub(crate) fn event_id(&self) -> Option<&str> {
        match self {
            EventCommand::Create(_) => None,
            EventCommand::Update(command) => Some(command.event_id.as_str()),
            EventCommand::Close(command) => Some(command.event_id.as_str()),
        }
    }

    pub(crate) fn thing_id(&self) -> Option<&str> {
        match self {
            EventCommand::Create(command) => command.thing_id.as_deref(),
            EventCommand::Update(command) => command.thing_id.as_deref(),
            EventCommand::Close(command) => command.thing_id.as_deref(),
        }
    }

    pub(crate) fn event_time(&self) -> Option<i64> {
        match self {
            EventCommand::Create(command) => command.event_time,
            EventCommand::Update(command) => command.event_time,
            EventCommand::Close(command) => command.event_time,
        }
    }

    pub(crate) fn started_at(&self) -> Option<i64> {
        match self {
            EventCommand::Create(command) => command.started_at,
            EventCommand::Update(_) | EventCommand::Close(_) => None,
        }
    }

    pub(crate) fn ended_at(&self) -> Option<i64> {
        match self {
            EventCommand::Close(command) => command.ended_at,
            EventCommand::Create(_) | EventCommand::Update(_) => None,
        }
    }

    pub(crate) fn patch(&self) -> &P {
        match self {
            EventCommand::Create(command) => &command.patch,
            EventCommand::Update(command) => &command.patch,
            EventCommand::Close(command) => &command.patch,
        }
    }
}

impl EventCommand<EventPatch> {
    pub(crate) async fn normalize(
        self,
        idempotency: &(dyn IdempotencyStore + Send + Sync),
        channel_id: [u8; 16],
        channel_id_text: String,
        now_millis: i64,
    ) -> Result<NormalizedEnvelope<NormalizedEventCommand>, CoreError> {
        let action_name = self.action_name();
        let kind = self.kind();
        let patch = self.patch();
        if self.op_id().is_some() {
            return Err(CoreError::validation_code(
                "op_id is generated by gateway and must not be provided",
                "op_id_not_allowed",
            ));
        }
        let op_id = OpId::generate(now_millis);
        let thing_id = self
            .thing_id()
            .map(|raw| EntityId::parse(raw, "thing_id").map(EntityId::into_inner))
            .transpose()?;
        let normalized_thing_id = thing_id.clone();
        let event_id = match self.event_id() {
            None => {
                ResolvedSemanticId::resolve_create(
                    idempotency,
                    SemanticScope::semantic_create_key(
                        &channel_id_text,
                        "event",
                        thing_id.as_deref(),
                        &op_id,
                    )
                    .as_str(),
                )
                .await?
                .semantic_id
            }
            Some(raw_event_id) => EntityId::parse(raw_event_id, "event_id")?.into_inner(),
        };

        if let Some(metadata) = patch.metadata.as_ref() {
            MetadataEntries::new(metadata).validate()?;
        }
        kind.validate_required_fields()?;

        let event_time = self.event_time().ok_or_else(|| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "event.route_rejected",
                action = %(action_name),
                reason = %("event_time_required")
            );
            CoreError::validation_code("event_time is required", "event_time_required")
        })?;

        let mut custom_data = HashMap::with_capacity(2);
        if let Some(metadata) = patch.metadata.as_ref().filter(|value| !value.is_empty()) {
            custom_data.insert(
                "metadata".to_string(),
                MetadataEntries::new(metadata).encode()?,
            );
        }
        if let Some(ciphertext) = patch.ciphertext.as_ref() {
            custom_data.insert("ciphertext".to_string(), ciphertext.clone());
        }

        let mut merged_profile = EventProfile::default();
        if let Some(title) = patch.title.as_ref() {
            merged_profile.title = Some(title.clone());
        }
        if let Some(description) = patch.description.as_ref() {
            merged_profile.description = Some(description.clone());
        }
        if let Some(status) = patch.status.as_ref() {
            merged_profile.status = Some(status.clone());
        }
        if let Some(message) = patch.message.as_ref() {
            merged_profile.message = Some(message.clone());
        }
        if let Some(severity) = patch.severity.as_ref() {
            merged_profile.severity = Some(severity.clone());
        }
        if let Some(tags) = patch.tags.as_ref() {
            merged_profile.tags = tags.clone();
        }
        merged_profile.started_at = self.started_at();
        merged_profile.ended_at = self.ended_at();
        if let Some(images) = patch.images.as_ref() {
            merged_profile.images = images.clone();
        }
        let merged_profile = if merged_profile.is_empty() {
            None
        } else {
            Some(merged_profile)
        };
        let attrs_json_in = patch
            .attrs
            .as_ref()
            .map(|attrs| {
                serde_json::to_string(attrs).map_err(|_| {
                    CoreError::validation_code(
                        "event attrs format is invalid",
                        "event_attrs_format_invalid",
                    )
                })
            })
            .transpose()?;

        let notification_title = patch.title.clone().or_else(|| {
            merged_profile
                .as_ref()
                .and_then(|profile| profile.title.clone())
        });
        let notification_body = patch.message.clone().or(patch.description.clone());
        let mut extra = HashMap::with_capacity(16);
        extra.insert("event_id".to_string(), event_id.clone());
        extra.insert(
            "domain_action".to_string(),
            kind.domain_action().as_str().to_string(),
        );
        extra.insert("occurred_at".to_string(), event_time.to_string());
        extra.insert("event_time".to_string(), event_time.to_string());
        if let Some(value) = thing_id.as_deref() {
            extra.insert("thing_id".to_string(), value.to_string());
        }
        if let Some(tags) = patch.tags.as_ref()
            && let Ok(serialized) = serde_json::to_string(tags)
        {
            extra.insert("tags".to_string(), serialized);
        }
        if let Some(images) = patch.images.as_ref()
            && let Ok(serialized) = serde_json::to_string(images)
        {
            extra.insert("images".to_string(), serialized);
        }
        if let Some(profile) = merged_profile.as_ref() {
            profile.insert_extra_fields(&mut extra);
        }
        if let Some(value) = attrs_json_in.as_deref() {
            extra.insert("attrs".to_string(), value.to_string());
        }

        Ok(NormalizedEnvelope {
            channel_id,
            channel_id_text,
            op_id: op_id.into_inner(),
            occurred_at: event_time,
            action: kind.domain_action(),
            command: NormalizedEventCommand {
                event_id: event_id.clone(),
                thing_id: normalized_thing_id.clone(),
                projection: DomainPayloadProjection {
                    entity: EntityRef::Event {
                        event_id,
                        thing_id: normalized_thing_id,
                    },
                    alert: AlertHint {
                        title: notification_title,
                        body: notification_body,
                        severity: None,
                        ttl: None,
                    },
                    custom_data,
                    extra_fields: extra,
                    delivery_policy: DomainDeliveryPolicy::for_model_action(
                        EntityKind::Event,
                        kind.domain_action(),
                    ),
                },
            },
        })
    }
}

impl EventCommandKind {
    pub(crate) const CREATE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Event,
        action: DomainActionKind::Create,
        required_fields: &["event_time"],
        forbidden_fields: &["event_id"],
        generated_id: Some(EntityIdKind::Event),
        required_existing_id: None,
        required_time_field: Some("event_time"),
    };

    pub(crate) const UPDATE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Event,
        action: DomainActionKind::Update,
        required_fields: &["event_id", "event_time"],
        forbidden_fields: &[],
        generated_id: None,
        required_existing_id: Some(EntityIdKind::Event),
        required_time_field: Some("event_time"),
    };

    pub(crate) const CLOSE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Event,
        action: DomainActionKind::Close,
        required_fields: &["event_id", "event_time"],
        forbidden_fields: &[],
        generated_id: None,
        required_existing_id: Some(EntityIdKind::Event),
        required_time_field: Some("event_time"),
    };

    pub(crate) fn spec(self) -> ActionSpec {
        match self {
            EventCommandKind::Create => Self::CREATE_SPEC,
            EventCommandKind::Update => Self::UPDATE_SPEC,
            EventCommandKind::Close => Self::CLOSE_SPEC,
        }
    }

    pub(crate) fn action_name(self) -> &'static str {
        match self {
            EventCommandKind::Create => "create",
            EventCommandKind::Update => "update",
            EventCommandKind::Close => "close",
        }
    }

    pub(crate) fn validate_required_fields(self) -> Result<(), CoreError> {
        let _ = self;
        Ok(())
    }

    fn domain_action(self) -> DomainAction {
        match self {
            EventCommandKind::Create => DomainAction::Create,
            EventCommandKind::Update => DomainAction::Update,
            EventCommandKind::Close => DomainAction::Close,
        }
    }
}

impl EventProfile {
    fn is_empty(&self) -> bool {
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

    fn insert_extra_fields(&self, extra: &mut HashMap<String, String>) {
        if let Some(value) = self.title.as_deref() {
            extra.insert("title".to_string(), value.to_string());
        }
        if let Some(value) = self.description.as_deref() {
            extra.insert("description".to_string(), value.to_string());
        }
        if let Some(value) = self.status.as_deref() {
            extra.insert("status".to_string(), value.to_string());
        }
        if let Some(value) = self.message.as_deref() {
            extra.insert("message".to_string(), value.to_string());
        }
        if let Some(value) = self.severity.as_deref() {
            extra.insert("severity".to_string(), value.to_string());
        }
        if !self.tags.is_empty()
            && let Ok(serialized) = serde_json::to_string(&self.tags)
        {
            extra.insert("tags".to_string(), serialized);
        }
        if !self.images.is_empty()
            && let Ok(serialized) = serde_json::to_string(&self.images)
        {
            extra.insert("images".to_string(), serialized);
        }
        if let Some(value) = self.started_at {
            extra.insert("started_at".to_string(), value.to_string());
        }
        if let Some(value) = self.ended_at {
            extra.insert("ended_at".to_string(), value.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::{
        storage::{OpDedupeReservation, SemanticIdReservation, StoreResult},
        util::decode_lower_hex_128,
    };

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
            unreachable!("event normalization should not reserve op pending")
        }

        async fn mark_op_sent(&self, _key: &str, _delivery_id: &str) -> StoreResult<bool> {
            unreachable!("event normalization should not mark op sent")
        }

        async fn clear_op_pending(&self, _key: &str, _delivery_id: &str) -> StoreResult<()> {
            unreachable!("event normalization should not clear op pending")
        }
    }

    #[tokio::test]
    async fn event_normalize_preserves_business_patch_fields() {
        let channel_id = decode_lower_hex_128("11111111111111111111111111111111")
            .expect("channel id should decode");
        let normalized = EventCommand::Update(EventUpdateCommand {
            op_id: None,
            event_id: "event-1".to_string(),
            thing_id: None,
            event_time: Some(1_710_000_000_000),
            patch: EventPatch {
                description: Some("  keep spacing  ".to_string()),
                ciphertext: Some("".to_string()),
                images: Some(vec!["img-1".to_string(), "img-1".to_string()]),
                ..EventPatch::default()
            },
        })
        .normalize(
            &FakeIdempotencyStore,
            channel_id,
            "11111111111111111111111111111111".to_string(),
            1_725_000_123_456,
        )
        .await
        .expect("event should normalize");

        let projection = normalized.command.projection;
        assert_eq!(
            projection.custom_data.get("ciphertext").map(String::as_str),
            Some("")
        );
        assert_eq!(
            projection
                .extra_fields
                .get("description")
                .map(String::as_str),
            Some("  keep spacing  ")
        );
        assert_eq!(
            projection.extra_fields.get("images").map(String::as_str),
            Some(r#"["img-1","img-1"]"#)
        );
    }
}
