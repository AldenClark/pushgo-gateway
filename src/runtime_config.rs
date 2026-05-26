use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayRuntimeProfile {
    Small,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayRuntimeProfileSelection {
    Small,
    Public,
}

#[derive(Debug, Clone, Copy)]
pub struct PrivateRuntimeTuning {
    pub session_ttl_secs: i64,
    pub grace_window_secs: u64,
    pub max_pending_per_device: usize,
    pub global_max_pending: usize,
    pub pull_limit: usize,
    pub ack_timeout_secs: u64,
    pub fallback_max_attempts: u32,
    pub fallback_max_backoff_secs: u64,
    pub retransmit_window_secs: u64,
    pub retransmit_max_per_window: u32,
    pub retransmit_max_per_tick: usize,
    pub retransmit_max_retries: u8,
    pub hot_cache_capacity: usize,
    pub default_ttl_secs: i64,
    pub online_fast_path_enabled: bool,
    pub fallback_task_queue_capacity: usize,
    pub connection_queue_capacity: usize,
    pub fallback_seed_limit: usize,
    pub maintenance_interval_secs: i64,
    pub fallback_due_batch: usize,
    pub active_claim_batch: usize,
    pub active_claim_max_rounds: usize,
    pub active_claim_process_budget: usize,
    pub idle_claim_batch: usize,
    pub idle_claim_max_rounds: usize,
    pub idle_claim_process_budget: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct MaintenanceRuntimeTuning {
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

#[derive(Debug, Clone, Copy)]
pub struct DispatchRuntimeTuning {
    pub worker_count: usize,
    pub queue_capacity: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct StatsRuntimeTuning {
    pub channel_capacity: usize,
    pub flush_event_threshold: usize,
    pub flush_interval_secs: u64,
    pub retained_row_limit: usize,
    pub sample_gateway_runtime_metrics: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SqliteRuntimeTuning {
    pub core_read_connections: u32,
    pub core_read_acquire_timeout: Duration,
    pub core_write_acquire_timeout: Duration,
    pub sidecar_acquire_timeout: Duration,
    pub busy_timeout: Duration,
    pub idle_timeout: Duration,
    pub statement_cache_capacity: usize,
    pub page_cache_kib: i64,
    pub wal_autocheckpoint: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ExternalDbRuntimeTuning {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct CacheRuntimeTuning {
    pub device_min: usize,
    pub device_max: usize,
    pub channel_info_min: usize,
    pub channel_info_max: usize,
    pub channel_devices_min: usize,
    pub channel_devices_max: usize,
    pub dispatch_targets_min: usize,
    pub dispatch_targets_max: usize,
    pub dispatch_targets_ttl_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderRuntimeTuning {
    pub apns_max_in_flight: usize,
    pub fcm_max_in_flight: usize,
    pub wns_max_in_flight: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct McpRuntimeTuning {
    pub access_token_ttl_secs: i64,
    pub refresh_token_absolute_ttl_secs: i64,
    pub refresh_token_idle_ttl_secs: i64,
    pub bind_session_ttl_secs: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeTuning {
    pub profile: GatewayRuntimeProfile,
    pub private: PrivateRuntimeTuning,
    pub maintenance: MaintenanceRuntimeTuning,
    pub dispatch: DispatchRuntimeTuning,
    pub stats: StatsRuntimeTuning,
    pub sqlite: SqliteRuntimeTuning,
    pub external_db: ExternalDbRuntimeTuning,
    pub cache: CacheRuntimeTuning,
    pub provider: ProviderRuntimeTuning,
    pub mcp: McpRuntimeTuning,
}

impl GatewayRuntimeProfile {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Public => "public",
        }
    }
}

impl GatewayRuntimeProfileSelection {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" => Some(Self::Small),
            "small" | "sqlite" | "private" | "single-node" | "single_node" => Some(Self::Small),
            "public" | "postgres" | "postgresql" | "pg" | "large" => Some(Self::Public),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Public => "public",
        }
    }

    #[must_use]
    pub fn resolve(self) -> GatewayRuntimeProfile {
        match self {
            Self::Small => GatewayRuntimeProfile::Small,
            Self::Public => GatewayRuntimeProfile::Public,
        }
    }
}

impl RuntimeTuning {
    #[must_use]
    pub fn for_profile(profile: GatewayRuntimeProfile) -> Self {
        match profile {
            GatewayRuntimeProfile::Small => Self::small(),
            GatewayRuntimeProfile::Public => Self::public(),
        }
    }

    #[must_use]
    fn small() -> Self {
        const DAY_SECS: i64 = 24 * 60 * 60;
        Self {
            profile: GatewayRuntimeProfile::Small,
            private: PrivateRuntimeTuning {
                session_ttl_secs: 3600,
                grace_window_secs: 60,
                max_pending_per_device: 96,
                global_max_pending: 100_000,
                pull_limit: 96,
                ack_timeout_secs: 3,
                fallback_max_attempts: 5,
                fallback_max_backoff_secs: 60,
                retransmit_window_secs: 10,
                retransmit_max_per_window: 64,
                retransmit_max_per_tick: 8,
                retransmit_max_retries: 5,
                hot_cache_capacity: 4_096,
                default_ttl_secs: 7 * DAY_SECS,
                online_fast_path_enabled: false,
                fallback_task_queue_capacity: 512,
                connection_queue_capacity: 32,
                fallback_seed_limit: 2_048,
                maintenance_interval_secs: 300,
                fallback_due_batch: 128,
                active_claim_batch: 128,
                active_claim_max_rounds: 2,
                active_claim_process_budget: 512,
                idle_claim_batch: 32,
                idle_claim_max_rounds: 1,
                idle_claim_process_budget: 64,
            },
            maintenance: MaintenanceRuntimeTuning {
                provider_pull_expired_batch: 512,
                private_stale_outbox_ttl_secs: 7 * DAY_SECS,
                orphan_device_ttl_secs: 14 * DAY_SECS,
                stale_subscription_ttl_secs: 120 * DAY_SECS,
                soft_deleted_device_ttl_secs: 30 * DAY_SECS,
                orphan_channel_ttl_secs: 180 * DAY_SECS,
                dedupe_retention_secs: 7 * DAY_SECS,
                audit_retention_secs: 30 * DAY_SECS,
                hourly_stats_retention_secs: 14 * DAY_SECS,
                daily_stats_retention_secs: 90 * DAY_SECS,
                delete_batch: 128,
                stale_subscription_cleanup_enabled: false,
                soft_deleted_device_cleanup_enabled: false,
                orphan_channel_cleanup_enabled: false,
                audit_retention_cleanup_enabled: true,
                stats_retention_cleanup_enabled: true,
            },
            dispatch: DispatchRuntimeTuning {
                worker_count: 2,
                queue_capacity: 256,
            },
            stats: StatsRuntimeTuning {
                channel_capacity: 512,
                flush_event_threshold: 256,
                flush_interval_secs: 10,
                retained_row_limit: 8_192,
                sample_gateway_runtime_metrics: false,
            },
            sqlite: SqliteRuntimeTuning {
                core_read_connections: 2,
                core_read_acquire_timeout: Duration::from_secs(5),
                core_write_acquire_timeout: Duration::from_secs(5),
                sidecar_acquire_timeout: Duration::from_millis(500),
                busy_timeout: Duration::from_secs(30),
                idle_timeout: Duration::from_secs(30),
                statement_cache_capacity: 24,
                page_cache_kib: 512,
                wal_autocheckpoint: 128,
            },
            external_db: ExternalDbRuntimeTuning {
                max_connections: 8,
                min_connections: 0,
                acquire_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(60),
                max_lifetime: Duration::from_secs(30 * 60),
            },
            cache: CacheRuntimeTuning {
                device_min: 64,
                device_max: 512,
                channel_info_min: 64,
                channel_info_max: 512,
                channel_devices_min: 64,
                channel_devices_max: 512,
                dispatch_targets_min: 64,
                dispatch_targets_max: 512,
                dispatch_targets_ttl_ms: 1_000,
            },
            provider: ProviderRuntimeTuning {
                apns_max_in_flight: 32,
                fcm_max_in_flight: 32,
                wns_max_in_flight: 16,
            },
            mcp: McpRuntimeTuning {
                access_token_ttl_secs: 900,
                refresh_token_absolute_ttl_secs: 30 * DAY_SECS,
                refresh_token_idle_ttl_secs: 7 * DAY_SECS,
                bind_session_ttl_secs: 600,
            },
        }
    }

    #[must_use]
    fn public() -> Self {
        const DAY_SECS: i64 = 24 * 60 * 60;
        let cpu = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4);
        let worker_count = cpu.clamp(4, 16);
        Self {
            profile: GatewayRuntimeProfile::Public,
            private: PrivateRuntimeTuning {
                session_ttl_secs: 3600,
                grace_window_secs: 60,
                max_pending_per_device: 200,
                global_max_pending: 5_000_000,
                pull_limit: 200,
                ack_timeout_secs: 15,
                fallback_max_attempts: 5,
                fallback_max_backoff_secs: 300,
                retransmit_window_secs: 10,
                retransmit_max_per_window: 128,
                retransmit_max_per_tick: 16,
                retransmit_max_retries: 5,
                hot_cache_capacity: 100_000,
                default_ttl_secs: 30 * DAY_SECS,
                online_fast_path_enabled: false,
                fallback_task_queue_capacity: 16_384,
                connection_queue_capacity: 128,
                fallback_seed_limit: 100_000,
                maintenance_interval_secs: 60,
                fallback_due_batch: 1_024,
                active_claim_batch: 1_024,
                active_claim_max_rounds: 4,
                active_claim_process_budget: 4_096,
                idle_claim_batch: 256,
                idle_claim_max_rounds: 1,
                idle_claim_process_budget: 256,
            },
            maintenance: MaintenanceRuntimeTuning {
                provider_pull_expired_batch: 4_096,
                private_stale_outbox_ttl_secs: 30 * DAY_SECS,
                orphan_device_ttl_secs: 30 * DAY_SECS,
                stale_subscription_ttl_secs: 120 * DAY_SECS,
                soft_deleted_device_ttl_secs: 30 * DAY_SECS,
                orphan_channel_ttl_secs: 180 * DAY_SECS,
                dedupe_retention_secs: 30 * DAY_SECS,
                audit_retention_secs: 180 * DAY_SECS,
                hourly_stats_retention_secs: 90 * DAY_SECS,
                daily_stats_retention_secs: 400 * DAY_SECS,
                delete_batch: 1_024,
                stale_subscription_cleanup_enabled: false,
                soft_deleted_device_cleanup_enabled: false,
                orphan_channel_cleanup_enabled: false,
                audit_retention_cleanup_enabled: true,
                stats_retention_cleanup_enabled: true,
            },
            dispatch: DispatchRuntimeTuning {
                worker_count,
                queue_capacity: (worker_count * 256).clamp(2_048, 16_384),
            },
            stats: StatsRuntimeTuning {
                channel_capacity: 8_192,
                flush_event_threshold: 1_024,
                flush_interval_secs: 2,
                retained_row_limit: 131_072,
                sample_gateway_runtime_metrics: true,
            },
            sqlite: SqliteRuntimeTuning {
                core_read_connections: 4,
                core_read_acquire_timeout: Duration::from_secs(5),
                core_write_acquire_timeout: Duration::from_secs(5),
                sidecar_acquire_timeout: Duration::from_secs(1),
                busy_timeout: Duration::from_secs(30),
                idle_timeout: Duration::from_secs(60),
                statement_cache_capacity: 64,
                page_cache_kib: 4_096,
                wal_autocheckpoint: 512,
            },
            external_db: ExternalDbRuntimeTuning {
                max_connections: 64,
                min_connections: 4,
                acquire_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(300),
                max_lifetime: Duration::from_secs(30 * 60),
            },
            cache: CacheRuntimeTuning {
                device_min: 256,
                device_max: 4_096,
                channel_info_min: 256,
                channel_info_max: 4_096,
                channel_devices_min: 512,
                channel_devices_max: 8_192,
                dispatch_targets_min: 512,
                dispatch_targets_max: 8_192,
                dispatch_targets_ttl_ms: 2_000,
            },
            provider: ProviderRuntimeTuning {
                apns_max_in_flight: 128,
                fcm_max_in_flight: 256,
                wns_max_in_flight: 128,
            },
            mcp: McpRuntimeTuning {
                access_token_ttl_secs: 900,
                refresh_token_absolute_ttl_secs: 30 * DAY_SECS,
                refresh_token_idle_ttl_secs: 7 * DAY_SECS,
                bind_session_ttl_secs: 600,
            },
        }
    }
}
