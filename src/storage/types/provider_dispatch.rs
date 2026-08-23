#[derive(Debug, Clone)]
pub struct ProviderDispatchOutboxRecord {
    pub job_id: String,
    pub provider: String,
    pub delivery_id: String,
    pub op_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub device_key: String,
    pub payload_blob: Vec<u8>,
    pub state: String,
    pub next_attempt_at: i64,
    pub accepted_at: i64,
    pub expires_at: i64,
    /// Durable acceptance order used only for latest-state coalescing.
    pub coalesce_order: i64,
    /// Latest-state work (Widget/Live Activity) replaces any older generation
    /// under the same job identity. Alert deliveries are never coalescible.
    pub coalescible: bool,
}

#[derive(Debug, Clone)]
pub struct ProviderDispatchOutboxLease {
    pub record: ProviderDispatchOutboxRecord,
    pub owner: String,
    pub lease_generation: i64,
    pub lease_until: i64,
    pub attempt_count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderDispatchSettlement {
    Accepted,
    Retry,
    PermanentFailure,
    Superseded,
    Expired,
}
