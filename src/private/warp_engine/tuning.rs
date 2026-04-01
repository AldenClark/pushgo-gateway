use warp_link::warp_link_core::{ServerConfig, TlsMode};

use crate::private::protocol::{
    APP_STATE_BACKGROUND, APP_STATE_FOREGROUND, PERF_TIER_BALANCED, PERF_TIER_HIGH, PERF_TIER_LOW,
};

pub fn default_server_config() -> ServerConfig {
    ServerConfig {
        hello_timeout_ms: 8_000,
        idle_timeout_ms: 72_000,
        max_outbound_wait_ms: 15_000,
        min_outbound_wait_ms: 5,
        quic_tls_mode: TlsMode::TerminateInWarp,
        tcp_tls_mode: TlsMode::TerminateInWarp,
        write_timeout_ms: 10_000,
        max_concurrent_sessions: 8_192,
        ..ServerConfig::default()
    }
}

#[derive(Clone, Copy)]
pub(super) struct SessionTuning {
    pub heartbeat_secs: u16,
    pub ping_interval_secs: u16,
    pub idle_timeout_secs: u16,
    pub max_backoff_secs: u16,
}

pub(super) fn resolve_tuning(perf_tier: Option<&str>, app_state: Option<&str>) -> SessionTuning {
    let tier = perf_tier
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| PERF_TIER_BALANCED.to_string());
    let state = app_state
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| APP_STATE_FOREGROUND.to_string());
    let background = state == APP_STATE_BACKGROUND;
    match (tier.as_str(), background) {
        (PERF_TIER_HIGH, false) => SessionTuning {
            heartbeat_secs: 12,
            ping_interval_secs: 6,
            idle_timeout_secs: 48,
            max_backoff_secs: 8,
        },
        (PERF_TIER_HIGH, true) => SessionTuning {
            heartbeat_secs: 18,
            ping_interval_secs: 9,
            idle_timeout_secs: 72,
            max_backoff_secs: 10,
        },
        (PERF_TIER_LOW, false) => SessionTuning {
            heartbeat_secs: 24,
            ping_interval_secs: 12,
            idle_timeout_secs: 84,
            max_backoff_secs: 16,
        },
        (PERF_TIER_LOW, true) => SessionTuning {
            heartbeat_secs: 40,
            ping_interval_secs: 20,
            idle_timeout_secs: 120,
            max_backoff_secs: 24,
        },
        (_, true) => SessionTuning {
            heartbeat_secs: 28,
            ping_interval_secs: 14,
            idle_timeout_secs: 96,
            max_backoff_secs: 14,
        },
        _ => SessionTuning {
            heartbeat_secs: 18,
            ping_interval_secs: 9,
            idle_timeout_secs: 72,
            max_backoff_secs: 10,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_tuning;

    #[test]
    fn high_perf_foreground_is_more_aggressive_than_background() {
        let foreground = resolve_tuning(Some("high"), Some("foreground"));
        let background = resolve_tuning(Some("high"), Some("background"));
        assert!(foreground.heartbeat_secs < background.heartbeat_secs);
        assert!(foreground.idle_timeout_secs < background.idle_timeout_secs);
    }

    #[test]
    fn unknown_perf_tier_falls_back_to_balanced_profile() {
        let tuning = resolve_tuning(Some("unknown"), Some("foreground"));
        assert_eq!(tuning.heartbeat_secs, 18);
        assert_eq!(tuning.ping_interval_secs, 9);
        assert_eq!(tuning.idle_timeout_secs, 72);
        assert_eq!(tuning.max_backoff_secs, 10);
    }
}
