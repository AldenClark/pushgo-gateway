use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ChannelStatsDailyDelta {
    pub channel_id: [u8; 16],
    pub bucket_date: String,
    pub messages_routed: i64,
    pub deliveries_attempted: i64,
    pub deliveries_acked: i64,
    pub private_enqueued: i64,
    pub provider_attempted: i64,
    pub provider_failed: i64,
    pub provider_success: i64,
    pub private_realtime_delivered: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DeviceStatsDailyDelta {
    pub device_key: String,
    pub bucket_date: String,
    pub messages_received: i64,
    pub messages_acked: i64,
    pub private_connected_count: i64,
    pub private_pull_count: i64,
    pub provider_success_count: i64,
    pub provider_failure_count: i64,
    pub private_outbox_enqueued_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GatewayStatsHourlyDelta {
    pub bucket_hour: String,
    pub messages_routed: i64,
    pub deliveries_attempted: i64,
    pub deliveries_acked: i64,
    pub private_outbox_depth_max: i64,
    pub dedupe_pending_max: i64,
    pub active_private_sessions_max: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct OpsStatsHourlyDelta {
    pub bucket_hour: String,
    pub metric_key: String,
    pub metric_value: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StatsBatchWrite {
    pub channels: Vec<ChannelStatsDailyDelta>,
    pub devices: Vec<DeviceStatsDailyDelta>,
    pub gateway: Vec<GatewayStatsHourlyDelta>,
    pub ops: Vec<OpsStatsHourlyDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceCleanupStats {
    pub private_outbox_pruned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutomationCounts {
    pub channel_count: usize,
    pub subscription_count: usize,
    pub delivery_dedupe_pending_count: usize,
}
