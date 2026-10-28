#[cfg(test)]
mod ordinary_private_tests {
    use super::*;

    fn envelope() -> protocol::DeliverEnvelope {
        protocol::DeliverEnvelope {
            delivery_id: "00000000000000000000000000000001".to_owned(),
            payload: Arc::from([1_u8]),
            ordinary: true,
            ordinary_expires_at: Some(i64::MAX),
        }
    }

    #[tokio::test]
    async fn resume_hint_never_erases_an_uncommitted_delivery_capability() {
        let (_dir, hub) = resume_cleanup_hub().await;
        let device = [44; 16];
        let first = hub.start_or_resume_session(device, None, 0).await;
        let (seq, issued) = hub.track_sent_outbound(device, envelope());
        for hint in [0, seq, seq + 100] {
            let resumed = hub
                .start_or_resume_session(device, Some(&first.resume_token), hint)
                .await;
            assert_eq!(resumed.resume_token, first.resume_token);
            assert!(
                hub.peek_delivery_by_seq(device, seq, &issued.delivery_id)
                    .is_some()
            );
        }
        assert_eq!(
            hub.ack_by_seq(device, seq, Some("another-delivery"))
                .await
                .unwrap(),
            None,
            "a mismatched explicit ACK cannot consume another delivery"
        );
        assert_eq!(
            hub.ack_by_seq(device, seq, Some(&issued.delivery_id))
                .await
                .unwrap(),
            Some(issued.delivery_id)
        );
        assert!(hub.snapshot_inflight(device).is_empty());
    }

    #[test]
    fn ordinary_retransmission_reuses_issued_sequence_and_shared_body() {
        let now = Instant::now();
        let mut state = ResumeState::fresh(now);
        let first = envelope();
        let body = first.payload.clone();
        let (original, _) = state.track_outbound(first.clone(), now);
        let (replayed, replay) = state.track_outbound(first, now);
        assert_eq!(original, replayed);
        assert_eq!(state.inflight.len(), 1);
        assert!(Arc::ptr_eq(&body, &replay.payload));
    }

    #[test]
    fn ordinary_encoding_preserves_text_and_structured_values() {
        let raw = serde_json::json!({
            "message_id": "stable-id",
            "body": "中文🙂\\\"\n".repeat(1024),
            "metadata": {"negative": -42, "fraction": 1.25, "items": [1, 2, 3]},
            "timestamp": 1792123456789_i64
        });
        let encoded = encode_ordinary_private_payload(&serde_json::to_vec(&raw).unwrap()).unwrap();
        let decoded = protocol::PrivatePayloadEnvelope::decode_postcard(&encoded).unwrap();
        assert_eq!(
            decoded.data.get("message_id").map(String::as_str),
            Some("stable-id")
        );
        assert_eq!(
            decoded.data.get("body"),
            raw.get("body")
                .and_then(|value| value.as_str())
                .map(|value| value.to_owned())
                .as_ref()
        );
        let metadata: serde_json::Value =
            serde_json::from_str(decoded.data.get("metadata").unwrap()).unwrap();
        assert_eq!(metadata, raw["metadata"]);
        assert_eq!(
            decoded.data.get("timestamp").map(String::as_str),
            Some("1792123456789")
        );
    }
    fn resume_cleanup_config() -> PrivateConfig {
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

    async fn resume_cleanup_hub() -> (tempfile::TempDir, PrivateHub) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("resume.sqlite").display()
        );
        let store = Storage::new(Some(&url)).await.unwrap();
        (dir, PrivateHub::new(store, &resume_cleanup_config()))
    }

    #[tokio::test]
    async fn sends_do_not_globally_scan_or_prune_other_resume_devices() {
        let (_dir, hub) = resume_cleanup_hub().await;
        let target = [255; 16];
        for size in [128_u128, 1_000, 10_000] {
            hub.resume_state.clear();
            let now = Instant::now();
            let old = now - hub.resume_ttl - Duration::from_secs(1);
            for index in 0..size {
                hub.resume_state
                    .insert(index.to_be_bytes(), ResumeState::fresh(old));
            }
            for _ in 0..1_000 {
                let (seq, tracked) = hub.track_sent_outbound(target, envelope());
                assert_eq!(seq, 1);
                assert_eq!(tracked.delivery_id, envelope().delivery_id);
            }
            assert_eq!(
                hub.resume_state.len(),
                size as usize + 1,
                "a send must not scan and remove unrelated devices"
            );
            hub.prune_stale_resume_state(Instant::now());
            assert_eq!(
                hub.resume_state.len(),
                1,
                "the existing maintenance sweep still reclaims all expired peers"
            );
            assert_eq!(hub.snapshot_inflight(target).len(), 1);
        }
    }

    #[tokio::test]
    async fn expired_target_is_reset_before_maintenance_without_extending_resume_ttl() {
        let (_dir, hub) = resume_cleanup_hub().await;
        let device = [41; 16];
        let old = Instant::now() - hub.resume_ttl - Duration::from_secs(1);
        let mut previous = ResumeState::fresh(old);
        let prior = previous.token.clone();
        previous.track_outbound(envelope(), old);
        hub.resume_state.insert(device, previous);
        let resumed = hub.start_or_resume_session(device, Some(&prior), 0).await;
        assert_ne!(resumed.resume_token, prior);
        assert!(hub.snapshot_inflight(device).is_empty());
        assert_eq!(hub.track_sent_outbound(device, envelope()).0, 1);
    }

    #[tokio::test]
    async fn online_reconnect_keeps_order_and_ack_capabilities_past_global_ttl() {
        let (_dir, hub) = resume_cleanup_hub().await;
        let device = [42; 16];
        let old = Instant::now() - hub.resume_ttl - Duration::from_secs(1);
        let mut state = ResumeState::fresh(old);
        let prior = state.token.clone();
        let first = envelope();
        let mut second = envelope();
        second.delivery_id = "00000000000000000000000000000002".into();
        state.track_outbound(first.clone(), old);
        state.track_outbound(second.clone(), old);
        hub.resume_state.insert(device, state);
        let (sender, _receiver) = flume::bounded(4);
        hub.register_connection(device, 1, TransportKind::Tcp, sender);
        hub.prune_stale_resume_state(Instant::now());
        let resumed = hub.start_or_resume_session(device, Some(&prior), 0).await;
        assert_eq!(resumed.resume_token, prior);
        let inflight = hub.snapshot_inflight(device);
        assert_eq!(
            inflight.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(
            hub.peek_delivery_by_seq(device, 1, &first.delivery_id)
                .is_some()
        );
        assert_eq!(
            hub.ack_by_seq(device, 1, Some(&first.delivery_id))
                .await
                .unwrap(),
            Some(first.delivery_id)
        );
        assert_eq!(
            hub.snapshot_inflight(device)[0].1.delivery_id,
            second.delivery_id
        );
        hub.unregister_connection(device, 1);
        assert!(!hub.remove_stale_resume_state(device, Instant::now()));
    }

    #[tokio::test]
    async fn ack_refresh_protects_a_previously_selected_cleanup_candidate() {
        let (_dir, hub) = resume_cleanup_hub().await;
        let device = [43; 16];
        let now = Instant::now();
        let old = now - hub.resume_ttl - Duration::from_secs(1);
        let mut previous = ResumeState::fresh(old);
        let item = envelope();
        previous.track_outbound(item.clone(), old);
        hub.resume_state.insert(device, previous);
        // This is the same candidate boundary used by a sweep: selection may
        // precede an ACK, while conditional removal runs after its timestamp refresh.
        assert!(hub.resume_state.get(&device).unwrap().updated_at <= old);
        assert_eq!(
            hub.ack_by_seq(device, 1, Some(&item.delivery_id))
                .await
                .unwrap(),
            Some(item.delivery_id)
        );
        assert!(!hub.remove_stale_resume_state(device, now));
        assert!(hub.resume_state.contains_key(&device));
    }

    #[tokio::test]
    async fn existing_maintenance_reclaims_idle_resume_but_keeps_durable_outbox() {
        let (_dir, hub) = resume_cleanup_hub().await;
        let device = [44; 16];
        let now_ms = chrono::Utc::now().timestamp_millis();
        let delivery = "00000000000000000000000000000003";
        let body: Arc<[u8]> = Arc::from(b"retained pending payload".as_slice());
        hub.enqueue_private_message(device, delivery, body.clone(), now_ms, now_ms + 60_000)
            .await
            .unwrap();
        let old = Instant::now() - hub.resume_ttl - Duration::from_secs(1);
        hub.resume_state.insert(device, ResumeState::fresh(old));
        hub.run_maintenance_cleanup(now_ms, MaintenanceCleanupConfig::default())
            .await
            .unwrap();
        assert!(
            !hub.resume_state.contains_key(&device),
            "even a single idle state is reclaimed"
        );
        assert!(hub.is_delivery_pending(device, delivery).await.unwrap());
        let bootstrap = hub.build_bootstrap_queues(device, 16).await.unwrap();
        assert_eq!(bootstrap.pending.len(), 1);
        assert_eq!(bootstrap.pending[0].delivery_id, delivery);
        assert_eq!(bootstrap.pending[0].payload.as_ref(), body.as_ref());
    }
}
