#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchSubmissionRecord {
    pub dedupe_key: String,
    pub delivery_id: String,
    pub op_id: String,
    pub payload_version: i32,
    pub payload_blob: Vec<u8>,
    /// Database-issued total order for this durable acceptance. Zero denotes
    /// a payload written before the v12 ordering repair.
    pub acceptance_order: i64,
    pub accepted_at: i64,
    pub expires_at: i64,
}
