use chrono::Utc;

use crate::{
    api::Error,
    app::AppState,
    storage::{SemanticIdReservation, StoreError},
    util::generate_hex_id_128,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeliveryId(String);

impl DeliveryId {
    pub(crate) async fn reserve(state: &AppState, created_at: i64) -> Result<Self, Error> {
        const MAX_ATTEMPTS: usize = 4;
        for _ in 0..MAX_ATTEMPTS {
            let delivery_id = generate_hex_id_128();
            let dedupe_key = format!("delivery:{delivery_id}");
            let inserted = state
                .store
                .reserve_delivery_dedupe(dedupe_key.as_str(), &delivery_id, created_at)
                .await
                .map_err(internal_store_error)?;
            if inserted {
                return Ok(Self(delivery_id));
            }
        }
        Err(Error::Internal(
            "unable to reserve unique delivery id".to_string(),
        ))
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpId(String);

impl OpId {
    pub(crate) fn parse(raw: &str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(Error::validation("op_id must not be empty"));
        }
        if trimmed.len() > 128 {
            return Err(Error::validation("op_id is too long"));
        }
        if !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '-')
        {
            return Err(Error::validation("op_id format is invalid"));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub(crate) fn resolve(raw: Option<&str>) -> Result<Self, Error> {
        match raw {
            Some(value) => Self::parse(value),
            None => Ok(Self(generate_hex_id_128())),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

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
    pub semantic_id: String,
}

impl ResolvedSemanticId {
    pub(crate) async fn resolve_create(state: &AppState, dedupe_key: &str) -> Result<Self, Error> {
        const MAX_ATTEMPTS: usize = 8;
        let created_at = Utc::now().timestamp_millis();
        for _ in 0..MAX_ATTEMPTS {
            let semantic_id = generate_hex_id_128();
            match state
                .store
                .reserve_semantic_id(dedupe_key, &semantic_id, created_at)
                .await
                .map_err(internal_store_error)?
            {
                SemanticIdReservation::Reserved => return Ok(Self { semantic_id }),
                SemanticIdReservation::Existing { semantic_id } => {
                    return Ok(Self { semantic_id });
                }
                SemanticIdReservation::Collision => continue,
            }
        }
        Err(Error::Internal(
            "unable to reserve unique semantic id".to_string(),
        ))
    }
}

pub(crate) fn wakeup_data_with_delivery_id(
    wakeup_template: &hashbrown::HashMap<String, String>,
    delivery_id: &str,
) -> hashbrown::HashMap<String, String> {
    let mut data = wakeup_template.clone();
    data.insert("delivery_id".to_string(), delivery_id.to_string());
    data
}

fn normalize_scope_component(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn internal_store_error(error: StoreError) -> Error {
    Error::Internal(error.to_string())
}
