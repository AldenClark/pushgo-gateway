use super::*;
use crate::routing::derive_private_device_id;
use crate::storage::{MaintenanceCleanupConfig, OUTBOX_STATUS_CLAIMED};
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
        online_fast_path_enabled: false,
        maintenance_cleanup: MaintenanceCleanupConfig::default(),
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

#[tokio::test]
async fn enqueue_private_delivery_evicts_oldest_pending_when_device_capacity_is_full() {
    let ctx = StateTestContext::new().await;
    let device_id = derive_private_device_id("capacity-evict-device");
    let now = chrono::Utc::now().timestamp_millis();

    for index in 0..ctx.state.config.max_pending_per_device {
        ctx.state
            .enqueue_private_delivery(
                device_id,
                &format!("delivery-old-{index:02}"),
                std::sync::Arc::from([index as u8]),
                now + index as i64,
                now + 600_000,
            )
            .await
            .expect("initial enqueue should succeed");
    }

    ctx.state
        .enqueue_private_delivery(
            device_id,
            "delivery-new",
            std::sync::Arc::from([255u8]),
            now + 10_000,
            now + 600_000,
        )
        .await
        .expect("new enqueue should evict oldest pending instead of failing");

    let store = ctx.state.hub.store();
    assert_eq!(
        store
            .count_private_outbox_for_device(device_id)
            .await
            .expect("outbox count should succeed"),
        ctx.state.config.max_pending_per_device
    );
    assert!(
        store
            .load_private_outbox_entry(device_id, "delivery-old-00")
            .await
            .expect("oldest lookup should succeed")
            .is_none(),
        "oldest pending entry should be evicted"
    );
    assert!(
        store
            .load_private_outbox_entry(device_id, "delivery-old-01")
            .await
            .expect("next oldest lookup should succeed")
            .is_some(),
        "only one pending entry should be evicted"
    );
    assert!(
        store
            .load_private_outbox_entry(device_id, "delivery-new")
            .await
            .expect("new delivery lookup should succeed")
            .is_some(),
        "new delivery should be enqueued"
    );
}

#[tokio::test]
async fn enqueue_private_delivery_does_not_evict_claimed_entries_for_capacity() {
    let ctx = StateTestContext::new().await;
    let device_id = derive_private_device_id("capacity-claimed-device");
    let now = chrono::Utc::now().timestamp_millis();
    let store = ctx.state.hub.store();

    for index in 0..ctx.state.config.max_pending_per_device {
        let delivery_id = format!("delivery-claimed-{index:02}");
        let message = PrivateMessage {
            payload: vec![index as u8].into(),
            size: 1,
            sent_at: now + index as i64,
            expires_at: now + 600_000,
        };
        store
            .insert_private_message(&delivery_id, &message)
            .await
            .expect("claimed message insert should succeed");
        store
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id,
                    status: OUTBOX_STATUS_CLAIMED.to_string(),
                    attempts: 0,
                    occurred_at: now + index as i64,
                    created_at: now + index as i64,
                    claimed_at: Some(now + index as i64),
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now + 30_000,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now + index as i64,
                },
            )
            .await
            .expect("claimed outbox enqueue should succeed");
    }

    let err = ctx
        .state
        .enqueue_private_delivery(
            device_id,
            "delivery-new",
            std::sync::Arc::from([255u8]),
            now + 10_000,
            now + 600_000,
        )
        .await
        .expect_err("capacity full with no pending entries should remain too busy");
    assert!(matches!(err, crate::Error::TooBusy));
    assert!(
        store
            .load_private_outbox_entry(device_id, "delivery-new")
            .await
            .expect("new delivery lookup should succeed")
            .is_none(),
        "claimed entries must not be evicted to admit new delivery"
    );
}
