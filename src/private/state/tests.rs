use super::*;
use crate::routing::derive_private_device_id;
use tempfile::{TempDir, tempdir};

struct StateTestContext {
    _dir: TempDir,
    state: PrivateState,
}

impl StateTestContext {
    async fn new() -> Self {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("gateway-state.sqlite");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
        let storage = Storage::new(Some(db_url.as_str()))
            .await
            .expect("storage should initialize");
        let stats = StatsCollector::spawn(storage.clone());
        let state = PrivateState::new(
            storage,
            test_private_config(),
            Arc::new(DeviceRegistry::new()),
            stats,
        );
        Self { _dir: dir, state }
    }
}

fn test_private_config() -> PrivateConfig {
    PrivateConfig {
        private_quic_bind: None,
        private_tcp_bind: None,
        tcp_tls_offload: false,
        tcp_proxy_protocol: false,
        private_tls_cert_path: None,
        private_tls_key_path: None,
        session_ttl_secs: 60,
        grace_window_secs: 10,
        max_pending_per_device: 16,
        global_max_pending: 64,
        pull_limit: 32,
        ack_timeout_secs: 5,
        fallback_max_attempts: 3,
        fallback_max_backoff_secs: 60,
        retransmit_window_secs: 30,
        retransmit_max_per_window: 10,
        retransmit_max_per_tick: 16,
        retransmit_max_retries: 3,
        hot_cache_capacity: 64,
        default_ttl_secs: 60,
        gateway_token: None,
    }
    .normalized()
}

#[tokio::test]
async fn automation_stats_track_revocation_and_reset() {
    let ctx = StateTestContext::new().await;
    let device_key = "state-test-device";
    let device_id = derive_private_device_id(device_key);

    assert_eq!(
        ctx.state.automation_stats(),
        PrivateAutomationStats::default()
    );

    ctx.state.revoke_device_key(device_key);
    assert!(ctx.state.is_device_revoked(device_id));
    assert_eq!(ctx.state.automation_stats().revoked_device_count, 1);

    ctx.state.unrevoke_device_key(device_key);
    assert!(!ctx.state.is_device_revoked(device_id));

    ctx.state.revoke_device_key(device_key);
    ctx.state.automation_reset();
    assert_eq!(
        ctx.state.automation_stats(),
        PrivateAutomationStats::default()
    );
}

#[tokio::test]
async fn begin_shutdown_marks_state_and_wakes_waiters() {
    let ctx = StateTestContext::new().await;
    let wait = ctx.state.wait_for_shutdown();

    ctx.state.begin_shutdown();

    tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .expect("shutdown wait should finish promptly");
    assert!(ctx.state.is_shutting_down());
    assert!(
        ctx.state.session_coord_owner().starts_with("gateway-"),
        "session coordinator owner should remain gateway-scoped"
    );
}
