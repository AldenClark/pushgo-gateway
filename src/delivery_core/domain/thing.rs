use crate::{
    delivery_core::{error::CoreError, payload::EntityKind, store::idempotency::IdempotencyStore},
    value::{EntityId, MetadataEntries, OpId},
};
use hashbrown::HashMap;
use serde_json::{Map as JsonMap, Value as JsonValue};

use super::{
    common::DomainAction,
    ids::{ResolvedSemanticId, SemanticScope},
    projection::{
        AlertHint, DomainDeliveryPolicy, DomainPayloadProjection, EntityRef, NormalizedEnvelope,
    },
    spec::{ActionSpec, DomainActionKind, DomainModelKind, EntityIdKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThingCommandKind {
    Create,
    Update,
    Archive,
    Delete,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingCreateCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) created_at: Option<i64>,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingUpdateCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: String,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingArchiveCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: String,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) struct ThingDeleteCommand<P> {
    pub(crate) op_id: Option<String>,
    pub(crate) thing_id: String,
    pub(crate) deleted_at: Option<i64>,
    pub(crate) patch: P,
}

#[derive(Debug, Clone)]
pub(crate) enum ThingCommand<P> {
    Create(ThingCreateCommand<P>),
    Update(ThingUpdateCommand<P>),
    Archive(ThingArchiveCommand<P>),
    Delete(ThingDeleteCommand<P>),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ThingPatch {
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) external_ids: Option<JsonMap<String, JsonValue>>,
    pub(crate) location_type: Option<String>,
    pub(crate) location_value: Option<String>,
    pub(crate) primary_image: Option<String>,
    pub(crate) images: Option<Vec<String>>,
    pub(crate) ciphertext: Option<String>,
    pub(crate) observed_at: Option<i64>,
    pub(crate) attrs: Option<JsonMap<String, JsonValue>>,
    pub(crate) metadata: Option<JsonMap<String, JsonValue>>,
}

#[derive(Debug, Clone, Default)]
struct ThingProfile {
    title: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    primary_image: Option<String>,
    images: Vec<String>,
    created_at: Option<i64>,
    deleted_at: Option<i64>,
    external_ids: Option<JsonMap<String, JsonValue>>,
    location_type: Option<String>,
    location_value: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedThingCommand {
    pub(crate) thing_id: String,
    pub(crate) projection: DomainPayloadProjection,
}

impl<P> ThingCommand<P> {
    pub(crate) fn kind(&self) -> ThingCommandKind {
        match self {
            ThingCommand::Create(_) => ThingCommandKind::Create,
            ThingCommand::Update(_) => ThingCommandKind::Update,
            ThingCommand::Archive(_) => ThingCommandKind::Archive,
            ThingCommand::Delete(_) => ThingCommandKind::Delete,
        }
    }

    pub(crate) fn action_name(&self) -> &'static str {
        self.kind().action_name()
    }

    pub(crate) fn op_id(&self) -> Option<&str> {
        match self {
            ThingCommand::Create(command) => command.op_id.as_deref(),
            ThingCommand::Update(command) => command.op_id.as_deref(),
            ThingCommand::Archive(command) => command.op_id.as_deref(),
            ThingCommand::Delete(command) => command.op_id.as_deref(),
        }
    }

    pub(crate) fn thing_id(&self) -> Option<&str> {
        match self {
            ThingCommand::Create(_) => None,
            ThingCommand::Update(command) => Some(command.thing_id.as_str()),
            ThingCommand::Archive(command) => Some(command.thing_id.as_str()),
            ThingCommand::Delete(command) => Some(command.thing_id.as_str()),
        }
    }

    pub(crate) fn created_at(&self) -> Option<i64> {
        match self {
            ThingCommand::Create(command) => command.created_at,
            ThingCommand::Update(_) | ThingCommand::Archive(_) | ThingCommand::Delete(_) => None,
        }
    }

    pub(crate) fn deleted_at(&self) -> Option<i64> {
        match self {
            ThingCommand::Delete(command) => command.deleted_at,
            ThingCommand::Create(_) | ThingCommand::Update(_) | ThingCommand::Archive(_) => None,
        }
    }

    pub(crate) fn patch(&self) -> &P {
        match self {
            ThingCommand::Create(command) => &command.patch,
            ThingCommand::Update(command) => &command.patch,
            ThingCommand::Archive(command) => &command.patch,
            ThingCommand::Delete(command) => &command.patch,
        }
    }
}

impl ThingCommand<ThingPatch> {
    pub(crate) async fn normalize(
        self,
        idempotency: &(dyn IdempotencyStore + Send + Sync),
        channel_id: [u8; 16],
        channel_id_text: String,
    ) -> Result<NormalizedEnvelope<NormalizedThingCommand>, CoreError> {
        let action_name = self.action_name();
        let kind = self.kind();
        let patch = self.patch();
        let op_id = OpId::resolve(self.op_id())?;
        let thing_id = match self.thing_id() {
            None => {
                ResolvedSemanticId::resolve_create(
                    idempotency,
                    SemanticScope::semantic_create_key(&channel_id_text, "thing", None, &op_id)
                        .as_str(),
                )
                .await?
                .semantic_id
            }
            Some(raw_thing_id) => EntityId::parse(raw_thing_id, "thing_id")?.into_inner(),
        };

        if let Some(metadata) = patch.metadata.as_ref() {
            MetadataEntries::new(metadata).validate()?;
        }
        let observed_at = patch.observed_at.ok_or_else(|| {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "thing.route_rejected",
                action = %(action_name),
                reason = %("observed_at_required")
            );
            CoreError::validation_code("observed_at is required", "observed_at_required")
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

        let mut merged_profile = ThingProfile::default();
        if let Some(title) = patch.title.clone() {
            merged_profile.title = Some(title);
        }
        if let Some(description) = patch.description.clone() {
            merged_profile.description = Some(description);
        }
        if let Some(tags) = patch.tags.as_ref() {
            merged_profile.tags = tags.clone();
        }
        merged_profile.created_at = self.created_at();
        if let Some(image) = patch.primary_image.clone() {
            merged_profile.primary_image = Some(image);
        }
        if let Some(images) = patch.images.as_ref() {
            merged_profile.images = images.clone();
        }
        merged_profile.deleted_at = self.deleted_at();
        if let Some(external_ids) = patch.external_ids.as_ref() {
            merged_profile.external_ids = Some(external_ids.clone());
        }
        merged_profile.location_type = patch.location_type.clone();
        merged_profile.location_value = patch.location_value.clone();
        let merged_profile = if merged_profile.is_empty() {
            None
        } else {
            Some(merged_profile)
        };
        let attrs_json = patch
            .attrs
            .as_ref()
            .map(|attrs| {
                serde_json::to_string(attrs).map_err(|_| {
                    CoreError::validation_code(
                        "thing attrs format is invalid",
                        "thing_attrs_format_invalid",
                    )
                })
            })
            .transpose()?;
        let (notification_title, notification_body) =
            build_notification_content(patch, patch.description.clone(), |patch| {
                patch.title.as_deref()
            });
        let mut extra = HashMap::with_capacity(20);
        extra.insert("occurred_at".to_string(), observed_at.to_string());
        extra.insert("thing_id".to_string(), thing_id.clone());
        extra.insert(
            "domain_action".to_string(),
            kind.domain_action().as_str().to_string(),
        );
        if let Some(value) = attrs_json.as_deref() {
            extra.insert("attrs".to_string(), value.to_string());
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
        if let Some(external_ids) = patch.external_ids.as_ref()
            && let Ok(serialized) = serde_json::to_string(external_ids)
        {
            extra.insert("external_ids".to_string(), serialized);
        }
        if let Some(profile) = merged_profile.as_ref() {
            profile.insert_extra_fields(&mut extra);
        }

        Ok(NormalizedEnvelope {
            channel_id,
            channel_id_text,
            op_id: op_id.into_inner(),
            occurred_at: observed_at,
            action: kind.domain_action(),
            command: NormalizedThingCommand {
                thing_id: thing_id.clone(),
                projection: DomainPayloadProjection {
                    entity: EntityRef::Thing {
                        thing_id: thing_id.clone(),
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
                        EntityKind::Thing,
                        kind.domain_action(),
                    ),
                },
            },
        })
    }
}

impl ThingCommandKind {
    pub(crate) const CREATE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Thing,
        action: DomainActionKind::Create,
        required_fields: &["observed_at"],
        forbidden_fields: &["thing_id"],
        generated_id: Some(EntityIdKind::Thing),
        required_existing_id: None,
        required_time_field: Some("observed_at"),
    };

    pub(crate) const UPDATE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Thing,
        action: DomainActionKind::Update,
        required_fields: &["thing_id", "observed_at"],
        forbidden_fields: &[],
        generated_id: None,
        required_existing_id: Some(EntityIdKind::Thing),
        required_time_field: Some("observed_at"),
    };

    pub(crate) const ARCHIVE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Thing,
        action: DomainActionKind::Archive,
        required_fields: &["thing_id", "observed_at"],
        forbidden_fields: &[],
        generated_id: None,
        required_existing_id: Some(EntityIdKind::Thing),
        required_time_field: Some("observed_at"),
    };

    pub(crate) const DELETE_SPEC: ActionSpec = ActionSpec {
        model: DomainModelKind::Thing,
        action: DomainActionKind::Delete,
        required_fields: &["thing_id", "observed_at"],
        forbidden_fields: &[],
        generated_id: None,
        required_existing_id: Some(EntityIdKind::Thing),
        required_time_field: Some("observed_at"),
    };

    pub(crate) fn spec(self) -> ActionSpec {
        match self {
            ThingCommandKind::Create => Self::CREATE_SPEC,
            ThingCommandKind::Update => Self::UPDATE_SPEC,
            ThingCommandKind::Archive => Self::ARCHIVE_SPEC,
            ThingCommandKind::Delete => Self::DELETE_SPEC,
        }
    }

    pub(crate) fn action_name(self) -> &'static str {
        match self {
            ThingCommandKind::Create => "create",
            ThingCommandKind::Update => "update",
            ThingCommandKind::Archive => "archive",
            ThingCommandKind::Delete => "delete",
        }
    }

    fn domain_action(self) -> DomainAction {
        match self {
            ThingCommandKind::Create => DomainAction::Create,
            ThingCommandKind::Update => DomainAction::Update,
            ThingCommandKind::Archive => DomainAction::Archive,
            ThingCommandKind::Delete => DomainAction::Delete,
        }
    }
}

pub(crate) fn build_notification_content<P>(
    patch: &P,
    body: Option<String>,
    title: impl Fn(&P) -> Option<&str>,
) -> (Option<String>, Option<String>) {
    let requested_title = title(patch)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    (requested_title, body)
}

impl ThingProfile {
    fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.description.is_none()
            && self.tags.is_empty()
            && self.primary_image.is_none()
            && self.images.is_empty()
            && self.created_at.is_none()
            && self.deleted_at.is_none()
            && self.external_ids.is_none()
            && self.location_type.is_none()
            && self.location_value.is_none()
    }

    fn insert_extra_fields(&self, extra: &mut HashMap<String, String>) {
        if let Some(value) = self.title.as_deref() {
            extra.insert("title".to_string(), value.to_string());
        }
        if let Some(value) = self.description.as_deref() {
            extra.insert("description".to_string(), value.to_string());
        }
        if let Some(value) = self.primary_image.as_deref() {
            extra.insert("primary_image".to_string(), value.to_string());
        }
        if let Some(value) = self.created_at {
            extra.insert("created_at".to_string(), value.to_string());
        }
        if let Some(value) = self.deleted_at {
            extra.insert("deleted_at".to_string(), value.to_string());
        }
        if let Some(external_ids) = self.external_ids.as_ref()
            && let Ok(serialized) = serde_json::to_string(external_ids)
        {
            extra.insert("external_ids".to_string(), serialized);
        }
        if let Some(value) = self.location_type.as_deref() {
            extra.insert("location_type".to_string(), value.to_string());
        }
        if let Some(value) = self.location_value.as_deref() {
            extra.insert("location_value".to_string(), value.to_string());
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
            unreachable!("thing normalization should not reserve op pending")
        }

        async fn mark_op_sent(&self, _key: &str, _delivery_id: &str) -> StoreResult<bool> {
            unreachable!("thing normalization should not mark op sent")
        }

        async fn clear_op_pending(&self, _key: &str, _delivery_id: &str) -> StoreResult<()> {
            unreachable!("thing normalization should not clear op pending")
        }
    }

    #[tokio::test]
    async fn thing_normalize_preserves_business_patch_fields() {
        let channel_id = decode_lower_hex_128("11111111111111111111111111111111")
            .expect("channel id should decode");
        let normalized = ThingCommand::Update(ThingUpdateCommand {
            op_id: Some("op-1".to_string()),
            thing_id: "thing-1".to_string(),
            patch: ThingPatch {
                description: Some("  keep spacing  ".to_string()),
                primary_image: Some("  not-normalized  ".to_string()),
                images: Some(vec!["img-1".to_string(), "img-1".to_string()]),
                ciphertext: Some("".to_string()),
                observed_at: Some(1_710_000_000_000),
                ..ThingPatch::default()
            },
        })
        .normalize(
            &FakeIdempotencyStore,
            channel_id,
            "11111111111111111111111111111111".to_string(),
        )
        .await
        .expect("thing should normalize");

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
            projection
                .extra_fields
                .get("primary_image")
                .map(String::as_str),
            Some("  not-normalized  ")
        );
        assert_eq!(
            projection.extra_fields.get("images").map(String::as_str),
            Some(r#"["img-1","img-1"]"#)
        );
    }
}
