use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRouteAuditWrite {
    pub device_key: String,
    pub action: String,
    pub old_platform: Option<String>,
    pub new_platform: Option<String>,
    pub old_channel_type: Option<String>,
    pub new_channel_type: Option<String>,
    pub old_provider_token: Option<String>,
    pub new_provider_token: Option<String>,
    pub issue_reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionAuditWrite {
    pub channel_id: [u8; 16],
    pub device_key: String,
    pub action: String,
    pub platform: String,
    pub channel_type: String,
    pub created_at: i64,
}

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
    Sent,
}

impl DedupeState {
    pub fn as_str(self) -> &'static str {
        match self {
            DedupeState::Pending => "pending",
            DedupeState::Sent => "sent",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Result<Self, super::StoreError> {
        match value {
            "pending" => Ok(DedupeState::Pending),
            "sent" => Ok(DedupeState::Sent),
            _ => Err(super::StoreError::BinaryError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpDedupeReservation {
    Reserved,
    Pending { delivery_id: String },
    Sent { delivery_id: String },
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
