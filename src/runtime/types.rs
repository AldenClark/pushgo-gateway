use crate::storage::Platform;
use hashbrown::HashMap;

#[derive(Debug, Clone)]
pub struct NotificationIntent {
    pub trace_id: String,
    pub channel_id: [u8; 16],
    pub op_id: String,
    pub title: String,
    pub body: Option<String>,
    pub level: String,
    pub ttl: Option<i64>,
    pub data: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DeliveryPlan {
    pub trace_id: String,
    pub delivery_id: String,
    pub channel_id: [u8; 16],
    pub provider_targets: Vec<ProviderTarget>,
    pub private_targets: Vec<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub struct ProviderTarget {
    pub platform: Platform,
    pub token: String,
    pub wakeup_pull: bool,
}

#[derive(Debug, Clone)]
pub enum SessionCmd {
    StartOrResume {
        device_id: [u8; 16],
        resume_token: Option<String>,
        last_acked_seq: u64,
    },
    Ack {
        device_id: [u8; 16],
        seq: u64,
        delivery_id: String,
    },
    Disconnect {
        device_id: [u8; 16],
        conn_id: u64,
    },
}

#[derive(Debug, Clone)]
pub enum ProviderJob {
    Apns {
        trace_id: String,
        channel_id: [u8; 16],
        token: String,
    },
    Fcm {
        trace_id: String,
        channel_id: [u8; 16],
        token: String,
    },
    Wns {
        trace_id: String,
        channel_id: [u8; 16],
        token: String,
    },
}

#[derive(Debug, Clone)]
pub struct FallbackCmd {
    pub trace_id: String,
    pub device_id: [u8; 16],
    pub delivery_id: String,
    pub due_at_unix_secs: i64,
}

#[derive(Debug, Clone)]
pub struct AckEvent {
    pub trace_id: String,
    pub device_id: [u8; 16],
    pub delivery_id: String,
    pub seq: Option<u64>,
    pub ok: bool,
}
