use super::*;
use crate::routing::derive_private_device_id;
use crate::storage::{MaintenanceCleanupConfig, OUTBOX_STATUS_CLAIMED};
use tempfile::{TempDir, tempdir};

struct OrderedPayloadMap<'a>(&'a [(&'a str, &'a str)]);

impl serde::Serialize for OrderedPayloadMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(serde::Serialize)]
struct OrderedPayloadEnvelope<'a> {
    payload_version: u8,
    data: OrderedPayloadMap<'a>,
}

fn encode_ordered_private_payload(entries: &[(&str, &str)]) -> Vec<u8> {
    postcard::to_allocvec(&OrderedPayloadEnvelope {
        payload_version: crate::private::protocol::PRIVATE_PAYLOAD_VERSION_V1,
        data: OrderedPayloadMap(entries),
    })
    .expect("ordered private payload should encode")
}

fn private_message(payload: Vec<u8>, sent_at: i64, expires_at: i64) -> PrivateMessage {
    PrivateMessage {
        size: payload.len(),
        payload: Arc::from(payload),
        sent_at,
        expires_at,
    }
}

#[test]
fn private_payload_conflict_checks_full_semantics_and_timestamps() {
    let ascending = encode_ordered_private_payload(&[("a", "one"), ("b", "two")]);
    let descending = encode_ordered_private_payload(&[("b", "two"), ("a", "one")]);
    assert_ne!(
        ascending, descending,
        "fixture must differ at the byte level"
    );
    let canonical = private_message(ascending, 100, 200);
    assert!(!crate::private::hub::private_messages_conflict(
        &canonical,
        &private_message(descending, 100, 200)
    ));
    assert!(crate::private::hub::private_messages_conflict(
        &canonical,
        &private_message(
            encode_ordered_private_payload(&[("a", "changed")]),
            100,
            200,
        )
    ));
    assert!(crate::private::hub::private_messages_conflict(
        &canonical,
        &private_message(encode_ordered_private_payload(&[("a", "one")]), 101, 200)
    ));
    assert!(crate::private::hub::private_messages_conflict(
        &canonical,
        &private_message(encode_ordered_private_payload(&[("a", "one")]), 100, 201)
    ));
}

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
        let runtime_counters = RuntimeCounterCollector::spawn(storage.clone());
        let state = PrivateState::new(
            storage,
            test_private_config(),
            Arc::new(DeviceRegistry::new()),
            runtime_counters,
        );
        Self { _dir: dir, state }
    }
}

fn test_private_config() -> PrivateConfig {
    PrivateConfig {
        runtime_profile: crate::runtime_config::GatewayRuntimeProfile::Small,
        private_quic_bind: None,
        private_tcp_bind: None,
        mqtt: None,
        tcp_tls_enabled: false,
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
async fn shutdown_runtime_joins_owned_tasks_and_rejects_late_spawns() {
    let StateTestContext { _dir, state } = StateTestContext::new().await;
    let state = Arc::new(state);
    let worker_state = Arc::clone(&state);
    assert!(state.spawn_runtime_task("test_worker", async move {
        worker_state.wait_for_shutdown().await;
    }));

    let report = state.shutdown_runtime(Duration::from_secs(1)).await;

    assert_eq!(report.joined, 1);
    assert_eq!(report.panicked, 0);
    assert_eq!(report.aborted, 0);
    assert!(!state.spawn_runtime_task("late_worker", async {}));
}

#[tokio::test]
async fn full_connection_queue_never_blocks_other_private_delivery_work() {
    let ctx = StateTestContext::new().await;
    let device_id = derive_private_device_id("bounded-delivery-device");
    let (tx, _rx) = flume::bounded(1);
    let envelope = crate::private::protocol::DeliverEnvelope {
        delivery_id: "bounded-delivery".to_string(),
        payload: Arc::from([1u8]),
    };
    tx.try_send(envelope.clone())
        .expect("test queue should accept its first delivery");
    ctx.state
        .hub
        .register_connection(device_id, 1, TransportKind::Tcp, tx);

    let delivered = tokio::time::timeout(
        Duration::from_millis(100),
        ctx.state.hub.deliver_to_device(device_id, envelope),
    )
    .await
    .expect("a full per-device queue must not suspend the caller");

    assert!(!delivered);
}

#[tokio::test]
async fn cold_cache_conflicting_replay_uses_durable_canonical_payload_everywhere() {
    let ctx = StateTestContext::new().await;
    let device_id = derive_private_device_id("canonical-replay-device");
    let delivery_id = "canonical-replay-delivery";
    let now = chrono::Utc::now().timestamp_millis();
    let original = PrivateMessage {
        payload: Arc::from(b"canonical-a".as_slice()),
        size: b"canonical-a".len(),
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.state
        .hub
        .store()
        .insert_private_message(delivery_id, &original)
        .await
        .expect("original payload should pre-exist outside the cold hub cache");

    let outcomes = ctx
        .state
        .enqueue_private_deliveries(
            &[device_id],
            delivery_id,
            Arc::from(b"conflicting-b".as_slice()),
            now + 1,
            now + 120_000,
        )
        .await;
    let (_, outcome) = outcomes.into_iter().next().expect("one enqueue outcome");
    let outcome = outcome.expect("conflicting replay should converge on canonical bytes");
    assert_eq!(outcome.canonical_payload.as_ref(), b"canonical-a");

    let (tx, rx) = flume::bounded(1);
    ctx.state
        .hub
        .register_connection(device_id, 1, TransportKind::Tcp, tx);
    assert!(ctx.state.hub.try_deliver_to_device(
        device_id,
        crate::private::protocol::DeliverEnvelope {
            delivery_id: delivery_id.to_string(),
            payload: Arc::clone(&outcome.canonical_payload),
        },
    ));
    let realtime = rx
        .recv_async()
        .await
        .expect("realtime envelope should arrive");
    assert_eq!(realtime.payload.as_ref(), b"canonical-a");

    let cached = ctx
        .state
        .hub
        .load_private_message(delivery_id)
        .await
        .expect("cache lookup should succeed")
        .expect("canonical payload should remain cached");
    assert_eq!(cached.payload.as_ref(), b"canonical-a");
    let fallback = ctx
        .state
        .hub
        .pull_outbox(device_id, 1)
        .await
        .expect("fallback pull should succeed");
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback[0].1.payload.as_ref(), b"canonical-a");
}

#[tokio::test]
async fn repeated_legacy_map_order_replay_emits_no_payload_conflict_events() {
    let ctx = StateTestContext::new().await;
    let device_id = derive_private_device_id("semantic-replay-device");
    let delivery_id = "semantic-replay-delivery";
    let now = chrono::Utc::now().timestamp_millis();
    let canonical = encode_ordered_private_payload(&[("a", "one"), ("b", "two")]);
    let replay = encode_ordered_private_payload(&[("b", "two"), ("a", "one")]);
    assert_ne!(
        canonical, replay,
        "fixture must reproduce old byte instability"
    );
    ctx.state
        .hub
        .store()
        .insert_private_message(
            delivery_id,
            &PrivateMessage {
                size: canonical.len(),
                payload: Arc::from(canonical),
                sent_at: now,
                expires_at: now + 60_000,
            },
        )
        .await
        .expect("legacy canonical payload should persist");

    for _ in 0..100 {
        let outcomes = ctx
            .state
            .enqueue_private_deliveries(
                &[device_id],
                delivery_id,
                Arc::from(replay.clone()),
                now,
                now + 60_000,
            )
            .await;
        assert!(outcomes[0].1.is_ok());
    }

    assert_eq!(
        ctx.state.hub.payload_conflict_events(),
        0,
        "semantic replays must stay idle instead of emitting a warning per recovery poll"
    );
}

#[tokio::test]
async fn enqueue_private_delivery_rejects_before_evicting_accepted_work() {
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
        .expect_err("capacity must reject new work without evicting accepted work");
    assert!(matches!(err, crate::Error::TooBusy));

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
            .is_some(),
        "oldest accepted entry must be preserved"
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
            .is_none(),
        "rejected delivery must not be partially enqueued"
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
                    claimed_by: None,
                    claim_generation: 0,
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

#[tokio::test]
async fn acknowledged_delivery_replay_is_not_accepted_for_realtime_acceleration() {
    let ctx = StateTestContext::new().await;
    let device_id = derive_private_device_id("terminal-replay-device");
    let delivery_id = "terminal-replay-delivery";
    let now = chrono::Utc::now().timestamp_millis();

    ctx.state
        .enqueue_private_delivery(
            device_id,
            delivery_id,
            Arc::from([1u8, 2, 3]),
            now,
            now + 60_000,
        )
        .await
        .expect("initial delivery should enqueue");
    assert!(
        ctx.state
            .complete_terminal_delivery(device_id, delivery_id, None)
            .await
            .expect("terminal ACK should succeed")
    );

    let outcomes = ctx
        .state
        .enqueue_private_deliveries(
            &[device_id],
            delivery_id,
            Arc::from([9u8, 9, 9]),
            now + 1,
            now + 60_000,
        )
        .await;
    let outcome = outcomes
        .into_iter()
        .next()
        .expect("target result should exist")
        .1
        .expect("terminal replay should be an idempotent success");
    assert!(
        !outcome.accepted_for_delivery,
        "terminal replay must suppress realtime and MQTT accelerators"
    );
}
