//! Durable Private capabilities share the ordinary ledger's message identity.
//! Wire sequence/resume state stays in the bounded transport owner; it is never
//! accepted as a database ACK without a matching issued delivery capability.

#[derive(Clone, Debug)]
pub struct PrivateLedgerConfig {
    pub enabled: bool,
    pub max_pending_per_device: usize,
    pub max_pending: usize,
}

impl Default for PrivateLedgerConfig {
    fn default() -> Self {
        let tuning = pushgo_gateway::runtime_config::RuntimeTuning::for_profile(
            pushgo_gateway::runtime_config::GatewayRuntimeProfile::Small,
        );
        Self {
            enabled: false,
            max_pending_per_device: tuning.private.max_pending_per_device,
            max_pending: tuning.private.global_max_pending,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRoute {
    pub device_key: String,
    pub route_generation: i64,
    pub route_revision: i64,
}

#[derive(Clone)]
pub struct PrivateTicket {
    pub delivery_id: String,
    /// Frozen recipient identity, separate from the current consumer.
    pub receipt_owner: String,
    pub pull_owner: String,
    pub route_generation: i64,
    pub delivery_epoch: i64,
    pub claim_token: String,
    pub group_id: String,
    /// The single canonical ordinary JSON object, encoded to postcard only at
    /// the transport boundary. Never a second independently mutable message.
    pub payload: Vec<u8>,
    pub accepted_at: i64,
    pub expires_at: i64,
}
