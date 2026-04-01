use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryAuditPath {
    PrivateOutbox,
    Provider,
    Direct,
    WakeupPull,
}

impl DeliveryAuditPath {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryAuditPath::PrivateOutbox => "private_outbox",
            DeliveryAuditPath::Provider => "provider",
            DeliveryAuditPath::Direct => "direct",
            DeliveryAuditPath::WakeupPull => "wakeup_pull",
        }
    }

    pub fn parse_lossy(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "private_outbox" => Self::PrivateOutbox,
            "provider" => Self::Provider,
            "direct" => Self::Direct,
            "wakeup_pull" => Self::WakeupPull,
            _ => Self::Provider,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryAuditStatus {
    Enqueued,
    EnqueueFailed,
    PathRejected,
    SkippedPrivateRealtime,
}

impl DeliveryAuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryAuditStatus::Enqueued => "enqueued",
            DeliveryAuditStatus::EnqueueFailed => "enqueue_failed",
            DeliveryAuditStatus::PathRejected => "path_rejected",
            DeliveryAuditStatus::SkippedPrivateRealtime => "skipped_private_realtime",
        }
    }

    pub fn parse_lossy(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "enqueued" => Self::Enqueued,
            "enqueue_failed" => Self::EnqueueFailed,
            "path_rejected" => Self::PathRejected,
            "skipped_private_realtime" => Self::SkippedPrivateRealtime,
            _ => Self::EnqueueFailed,
        }
    }
}

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
pub struct DeliveryAuditWrite {
    pub delivery_id: String,
    pub channel_id: [u8; 16],
    pub device_key: String,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub op_id: Option<String>,
    pub path: DeliveryAuditPath,
    pub status: DeliveryAuditStatus,
    pub error_code: Option<String>,
    pub created_at: i64,
}

impl DeliveryAuditWrite {
    pub fn normalized(&self) -> Self {
        let mut normalized = self.clone();
        normalized.error_code = self.normalized_error_code();
        normalized
    }

    fn normalized_error_code(&self) -> Option<String> {
        let trimmed = self
            .error_code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())?;
        let mut out = trimmed.to_string();
        if out.len() > 64 {
            out.truncate(64);
        }
        Some(out)
    }
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
