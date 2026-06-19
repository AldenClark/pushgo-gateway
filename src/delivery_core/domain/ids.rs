use chrono::Utc;

use crate::{
    delivery_core::{error::CoreError, store::idempotency::IdempotencyStore},
    storage::SemanticIdReservation,
    util::generate_hex_id_128,
    value::OpId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticScope(String);

impl SemanticScope {
    pub(crate) fn new(channel_id: &str, entity_type: &str, entity_id: &str) -> Self {
        Self(format!(
            "{}:{}:{}",
            normalize_scope_component(channel_id),
            normalize_scope_component(entity_type),
            normalize_scope_component(entity_id)
        ))
    }

    pub(crate) fn semantic_create_key(
        channel_id: &str,
        entity_type: &str,
        scope_id: Option<&str>,
        op_id: &OpId,
    ) -> String {
        let scope = scope_id
            .map(normalize_scope_component)
            .unwrap_or_else(|| "-".to_string());
        format!(
            "semantic:{}:{}:{}:{}",
            normalize_scope_component(channel_id),
            normalize_scope_component(entity_type),
            scope,
            normalize_scope_component(op_id.as_str())
        )
    }

    pub(crate) fn op_dedupe_key(&self, op_id: &OpId) -> String {
        format!("op:{}:{}", self.0, op_id.as_str())
    }
}

pub(crate) struct ResolvedSemanticId {
    pub(crate) semantic_id: String,
}

impl ResolvedSemanticId {
    pub(crate) async fn resolve_create(
        store: &(dyn IdempotencyStore + Send + Sync),
        dedupe_key: &str,
    ) -> Result<Self, CoreError> {
        const MAX_ATTEMPTS: usize = 8;
        let created_at = Utc::now().timestamp_millis();
        let mut collisions = 0usize;
        for _ in 0..MAX_ATTEMPTS {
            let semantic_id = generate_hex_id_128();
            match store
                .reserve_semantic_id(dedupe_key, &semantic_id, created_at)
                .await?
            {
                SemanticIdReservation::Reserved => {
                    if collisions > 0 {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::INFO,
                            event = "domain.semantic_id_reserved_after_collision",
                            dedupe_key = %(crate::util::redact_text(dedupe_key)),
                            collisions = (collisions as u64)
                        );
                    }
                    return Ok(Self { semantic_id });
                }
                SemanticIdReservation::Existing { semantic_id } => {
                    return Ok(Self { semantic_id });
                }
                SemanticIdReservation::Collision => {
                    collisions = collisions.saturating_add(1);
                    continue;
                }
            }
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::ERROR,
            event = "domain.semantic_id_reserve_exhausted",
            dedupe_key = %(crate::util::redact_text(dedupe_key)),
            max_attempts = (MAX_ATTEMPTS as u64),
            collisions = (collisions as u64)
        );
        Err(CoreError::internal("unable to reserve unique semantic id"))
    }
}

fn normalize_scope_component(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}
