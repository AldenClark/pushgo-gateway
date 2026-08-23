use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryDedupeRecord {
    pub delivery_id: String,
    pub created_at: i64,
    pub state: DedupeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupeState {
    Pending,
    ProviderQueued,
    Sent,
    PartialFailure,
}

impl DedupeState {
    pub fn as_str(self) -> &'static str {
        match self {
            DedupeState::Pending => "pending",
            DedupeState::ProviderQueued => "provider_queued",
            DedupeState::Sent => "sent",
            DedupeState::PartialFailure => "partial_failure",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Result<Self, super::StoreError> {
        match value {
            "pending" => Ok(DedupeState::Pending),
            "provider_queued" => Ok(DedupeState::ProviderQueued),
            "sent" => Ok(DedupeState::Sent),
            "partial_failure" => Ok(DedupeState::PartialFailure),
            _ => Err(super::StoreError::BinaryError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpDedupeReservation {
    Reserved,
    ReservedSubmission { acceptance_order: i64 },
    FingerprintConflict { delivery_id: String },
    Pending { delivery_id: String },
    ProviderQueued { delivery_id: String },
    Sent { delivery_id: String },
    PartialFailure { delivery_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticIdReservation {
    Reserved,
    Existing { semantic_id: String },
    Collision,
}

#[derive(Debug, Clone)]
pub struct DispatchTargetsCacheEntry {
    pub cached_at_ms: i64,
    pub targets: Vec<super::DispatchTarget>,
}
