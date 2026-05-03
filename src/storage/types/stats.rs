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
    pub private_sessions_pruned: usize,
    pub private_outbox_pruned: usize,
    pub provider_pull_pruned: usize,
    pub orphan_devices_pruned: usize,
    pub stale_subscriptions_pruned: usize,
    pub soft_deleted_devices_pruned: usize,
    pub orphan_channels_pruned: usize,
    pub audit_rows_pruned: usize,
    pub hourly_stats_pruned: usize,
    pub daily_stats_pruned: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceCleanupConfig {
    pub provider_pull_expired_batch: usize,
    pub private_stale_outbox_ttl_secs: i64,
    pub orphan_device_ttl_secs: i64,
    pub stale_subscription_ttl_secs: i64,
    pub soft_deleted_device_ttl_secs: i64,
    pub orphan_channel_ttl_secs: i64,
    pub dedupe_retention_secs: i64,
    pub audit_retention_secs: i64,
    pub hourly_stats_retention_secs: i64,
    pub daily_stats_retention_secs: i64,
    pub delete_batch: usize,
    pub stale_subscription_cleanup_enabled: bool,
    pub soft_deleted_device_cleanup_enabled: bool,
    pub orphan_channel_cleanup_enabled: bool,
    pub audit_retention_cleanup_enabled: bool,
    pub stats_retention_cleanup_enabled: bool,
}

impl MaintenanceCleanupConfig {
    pub const fn defaults() -> Self {
        const DAY_SECS: i64 = 24 * 60 * 60;
        Self {
            provider_pull_expired_batch: 2048,
            private_stale_outbox_ttl_secs: 30 * DAY_SECS,
            orphan_device_ttl_secs: 30 * DAY_SECS,
            stale_subscription_ttl_secs: 120 * DAY_SECS,
            soft_deleted_device_ttl_secs: 30 * DAY_SECS,
            orphan_channel_ttl_secs: 180 * DAY_SECS,
            dedupe_retention_secs: 30 * DAY_SECS,
            audit_retention_secs: 180 * DAY_SECS,
            hourly_stats_retention_secs: 90 * DAY_SECS,
            daily_stats_retention_secs: 400 * DAY_SECS,
            delete_batch: 256,
            stale_subscription_cleanup_enabled: false,
            soft_deleted_device_cleanup_enabled: false,
            orphan_channel_cleanup_enabled: false,
            audit_retention_cleanup_enabled: false,
            stats_retention_cleanup_enabled: false,
        }
    }

    pub fn normalized(mut self) -> Self {
        self.provider_pull_expired_batch = normalize_batch(self.provider_pull_expired_batch, 2048);
        self.delete_batch = normalize_batch(self.delete_batch, 256);
        self.private_stale_outbox_ttl_secs =
            normalize_positive_secs(self.private_stale_outbox_ttl_secs, 30);
        self.orphan_device_ttl_secs = normalize_positive_secs(self.orphan_device_ttl_secs, 30);
        self.stale_subscription_ttl_secs =
            normalize_positive_secs(self.stale_subscription_ttl_secs, 120);
        self.soft_deleted_device_ttl_secs =
            normalize_positive_secs(self.soft_deleted_device_ttl_secs, 30);
        self.orphan_channel_ttl_secs = normalize_positive_secs(self.orphan_channel_ttl_secs, 180);
        self.dedupe_retention_secs = normalize_positive_secs(self.dedupe_retention_secs, 30);
        self.audit_retention_secs = normalize_positive_secs(self.audit_retention_secs, 180);
        self.hourly_stats_retention_secs =
            normalize_positive_secs(self.hourly_stats_retention_secs, 90);
        self.daily_stats_retention_secs =
            normalize_positive_secs(self.daily_stats_retention_secs, 400);
        self
    }

    pub fn private_stale_outbox_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.private_stale_outbox_ttl_secs)
    }

    pub fn orphan_device_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.orphan_device_ttl_secs)
    }

    pub fn stale_subscription_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.stale_subscription_ttl_secs)
    }

    pub fn soft_deleted_device_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.soft_deleted_device_ttl_secs)
    }

    pub fn orphan_channel_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.orphan_channel_ttl_secs)
    }

    pub fn audit_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.audit_retention_secs)
    }

    pub fn dedupe_before(self, now: i64) -> i64 {
        before_from_ttl(now, self.dedupe_retention_secs)
    }

    pub fn hourly_stats_before(self, now: i64) -> String {
        hour_bucket_from_millis(before_from_ttl(now, self.hourly_stats_retention_secs))
    }

    pub fn daily_stats_before(self, now: i64) -> String {
        day_bucket_from_millis(before_from_ttl(now, self.daily_stats_retention_secs))
    }
}

impl Default for MaintenanceCleanupConfig {
    fn default() -> Self {
        MaintenanceCleanupConfig::defaults()
    }
}

#[inline]
fn normalize_batch(value: usize, default_value: usize) -> usize {
    if value == 0 {
        default_value
    } else {
        value.min(100_000)
    }
}

#[inline]
fn normalize_positive_secs(value: i64, default_days: i64) -> i64 {
    const DAY_SECS: i64 = 24 * 60 * 60;
    if value <= 0 {
        default_days * DAY_SECS
    } else {
        value
    }
}

#[inline]
fn before_from_ttl(now: i64, ttl_secs: i64) -> i64 {
    now.saturating_sub(ttl_secs.saturating_mul(1000))
}

fn hour_bucket_from_millis(ts: i64) -> String {
    let secs = ts.div_euclid(1000);
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .format("%Y-%m-%dT%H")
        .to_string()
}

fn day_bucket_from_millis(ts: i64) -> String {
    let secs = ts.div_euclid(1000);
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .format("%Y-%m-%d")
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutomationCounts {
    pub channel_count: usize,
    pub subscription_count: usize,
    pub delivery_dedupe_pending_count: usize,
}

#[cfg(test)]
mod tests {
    use super::MaintenanceCleanupConfig;

    #[test]
    fn maintenance_cleanup_config_keeps_dedupe_retention_separate_from_audit_retention() {
        let config = MaintenanceCleanupConfig::default();
        assert_eq!(config.dedupe_retention_secs, 30 * 24 * 60 * 60);
        assert_eq!(config.audit_retention_secs, 180 * 24 * 60 * 60);
    }

    #[test]
    fn maintenance_cleanup_config_normalizes_zero_values_to_defaults() {
        let config = MaintenanceCleanupConfig {
            provider_pull_expired_batch: 0,
            dedupe_retention_secs: 0,
            audit_retention_secs: 0,
            delete_batch: 0,
            ..MaintenanceCleanupConfig::default()
        }
        .normalized();

        assert_eq!(config.provider_pull_expired_batch, 2048);
        assert_eq!(config.dedupe_retention_secs, 30 * 24 * 60 * 60);
        assert_eq!(config.audit_retention_secs, 180 * 24 * 60 * 60);
        assert_eq!(config.delete_batch, 256);
    }
}
