use super::*;
use crate::routing::derive_private_device_id;
use crate::storage::database::DedupeDatabaseAccess;

#[tokio::test]
async fn provider_retry_expiry_claim_uses_composite_index() {
    let ctx = setup_sqlite_storage("provider-retry-expiry-index").await;
    let mut dispatch = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("dispatch sidecar should open");
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN \
         SELECT job_id FROM provider_dispatch_outbox \
         WHERE provider = ? AND expires_at > ? \
           AND state = 'retry_wait' AND next_attempt_at <= ? \
         ORDER BY expires_at, next_attempt_at, accepted_at LIMIT 1",
    )
    .bind("APNS")
    .bind(1_i64)
    .bind(2_i64)
    .fetch_all(&mut dispatch)
    .await
    .expect("retry claim query plan should be available");
    assert!(
        plan.iter().any(|(_, _, _, detail)| {
            detail.contains("provider_dispatch_outbox_retry_expiry_idx")
        }),
        "near-TTL retry claim must use its composite index: {plan:?}"
    );
    assert!(
        plan.iter()
            .all(|(_, _, _, detail)| !detail.contains("USE TEMP B-TREE FOR ORDER BY")),
        "near-TTL retry claim must not sort the durable backlog: {plan:?}"
    );
}

#[tokio::test]
async fn coalescible_provider_job_fences_an_inflight_older_generation() {
    let ctx = setup_sqlite_storage("provider-coalescing-fence").await;
    let now = chrono::Utc::now().timestamp_millis();
    let first = ProviderDispatchOutboxRecord {
        job_id: "coalesced-widget-job".to_string(),
        provider: "APNS_WIDGETS".to_string(),
        delivery_id: "delivery-old".to_string(),
        op_id: Some("widget-op-old".to_string()),
        dedupe_key: Some("op:widget:message:old:widget-op-old".to_string()),
        device_key: "widget-device".to_string(),
        payload_blob: b"old".to_vec(),
        state: "pending".to_string(),
        next_attempt_at: now,
        accepted_at: now,
        expires_at: now + 60_000,
        coalesce_order: 1,
        coalescible: true,
    };
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&first)
            .await
            .unwrap()
    );
    let old_lease = ctx
        .storage
        .claim_provider_dispatch_job("APNS_WIDGETS", None, "old-owner", now, now + 30_000)
        .await
        .unwrap()
        .expect("old generation should lease");

    let replacement = ProviderDispatchOutboxRecord {
        delivery_id: "delivery-new".to_string(),
        payload_blob: b"new".to_vec(),
        accepted_at: now + 1,
        next_attempt_at: now + 1,
        expires_at: now + 60_001,
        coalesce_order: 2,
        ..first
    };
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&replacement)
            .await
            .unwrap()
    );
    assert!(
        !ctx.storage
            .settle_provider_dispatch_job(
                &old_lease,
                ProviderDispatchSettlement::Accepted,
                now + 2,
                200,
                None,
                now + 2,
            )
            .await
            .unwrap()
    );

    let stale_recovery = ProviderDispatchOutboxRecord {
        delivery_id: "delivery-stale-recovery".to_string(),
        payload_blob: b"stale".to_vec(),
        // This is deliberately later/equal wall time. The pre-fix
        // accepted_at guard would overwrite the new generation here.
        accepted_at: now + 100,
        next_attempt_at: now + 100,
        expires_at: now + 60_100,
        coalesce_order: 1,
        ..replacement.clone()
    };
    assert!(
        !ctx.storage
            .enqueue_provider_dispatch_job(&stale_recovery)
            .await
            .unwrap(),
        "older acceptance order must not overwrite a newer generation"
    );

    let new_lease = ctx
        .storage
        .claim_provider_dispatch_job("APNS_WIDGETS", None, "new-owner", now + 2, now + 30_002)
        .await
        .unwrap()
        .expect("replacement generation should remain pending");
    assert_eq!(new_lease.record.delivery_id, "delivery-new");
    assert_eq!(new_lease.record.payload_blob, b"new");
    assert_eq!(new_lease.record.expires_at, now + 60_001);
    assert_eq!(new_lease.record.coalesce_order, 2);
    assert!(new_lease.lease_generation > old_lease.lease_generation);
}

#[tokio::test]
async fn legacy_zero_order_coalescing_is_idempotent_only_within_one_submission() {
    let ctx = setup_sqlite_storage("provider-legacy-zero-order-fence").await;
    let now = chrono::Utc::now().timestamp_millis();
    let winner = ProviderDispatchOutboxRecord {
        job_id: "legacy-live-activity-job".to_string(),
        provider: "APNS_LIVE_ACTIVITY".to_string(),
        delivery_id: "legacy-submission-winner".to_string(),
        op_id: Some("legacy-op-winner".to_string()),
        dedupe_key: Some("op:submission:event:legacy:winner".to_string()),
        device_key: "legacy-live-activity-device".to_string(),
        payload_blob: b"winner".to_vec(),
        state: "pending".to_string(),
        next_attempt_at: now,
        accepted_at: now,
        expires_at: now + 60_000,
        coalesce_order: 0,
        coalescible: true,
    };
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&winner)
            .await
            .unwrap()
    );

    let same_submission_retry = ProviderDispatchOutboxRecord {
        payload_blob: b"winner-retry".to_vec(),
        ..winner.clone()
    };
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&same_submission_retry)
            .await
            .unwrap(),
        "the same frozen submission must remain idempotently materializable"
    );

    let stale_other_submission = ProviderDispatchOutboxRecord {
        delivery_id: "legacy-submission-stale".to_string(),
        op_id: Some("legacy-op-stale".to_string()),
        dedupe_key: Some("op:submission:event:legacy:stale".to_string()),
        payload_blob: b"stale".to_vec(),
        accepted_at: now + 1_000,
        next_attempt_at: now + 1_000,
        expires_at: now + 1_000,
        ..winner
    };
    assert!(
        !ctx.storage
            .enqueue_provider_dispatch_job(&stale_other_submission)
            .await
            .unwrap(),
        "legacy order zero from another submission must preserve the materialized winner"
    );

    let lease = ctx
        .storage
        .claim_provider_dispatch_job(
            "APNS_LIVE_ACTIVITY",
            Some("legacy-live-activity-job"),
            "legacy-winner-observer",
            now + 1_001,
            now + 21_001,
        )
        .await
        .unwrap()
        .expect("legacy winner should remain claimable");
    assert_eq!(lease.record.delivery_id, "legacy-submission-winner");
    assert_eq!(lease.record.payload_blob, b"winner-retry");
    assert_eq!(lease.record.expires_at, now + 60_000);
    assert_eq!(lease.record.coalesce_order, 0);
}

#[tokio::test]
async fn maintenance_prunes_only_terminal_provider_jobs_past_retention() {
    let ctx = setup_sqlite_storage("provider-terminal-retention").await;
    let now = 1_700_000_000_000_i64;
    let make_job = |suffix: &str, accepted_at: i64| ProviderDispatchOutboxRecord {
        job_id: format!("provider-terminal-{suffix}"),
        provider: "FCM".to_string(),
        delivery_id: format!("provider-terminal-delivery-{suffix}"),
        op_id: None,
        dedupe_key: None,
        device_key: format!("provider-terminal-device-{suffix}"),
        payload_blob: b"fixture".to_vec(),
        state: "pending".to_string(),
        next_attempt_at: accepted_at,
        accepted_at,
        expires_at: accepted_at + 60_000,
        coalesce_order: 0,
        coalescible: false,
    };
    let old = make_job("old", now);
    let recent = make_job("recent", now + 100);
    let open = make_job("open", now);
    for job in [&old, &recent, &open] {
        assert!(
            ctx.storage
                .enqueue_provider_dispatch_job(job)
                .await
                .expect("provider job should enqueue")
        );
    }
    for (job, owner, settled_at) in [
        (&old, "terminal-old-owner", now + 1),
        (&recent, "terminal-recent-owner", now + 101),
    ] {
        let lease = ctx
            .storage
            .claim_provider_dispatch_job(
                "FCM",
                Some(&job.job_id),
                owner,
                settled_at,
                settled_at + 20_000,
            )
            .await
            .expect("terminal job claim should succeed")
            .expect("terminal job should be claimable");
        assert!(
            ctx.storage
                .settle_provider_dispatch_job(
                    &lease,
                    ProviderDispatchSettlement::Accepted,
                    settled_at,
                    200,
                    None,
                    settled_at,
                )
                .await
                .expect("terminal settlement should succeed")
        );
    }

    assert_eq!(
        ctx.storage
            .cleanup_terminal_provider_dispatch_jobs(now + 50, 10)
            .await
            .expect("terminal cleanup should succeed"),
        1
    );
    let mut dispatch = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("dispatch sidecar should open");
    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT job_id FROM provider_dispatch_outbox ORDER BY job_id")
            .fetch_all(&mut dispatch)
            .await
            .expect("remaining provider jobs should list");
    assert_eq!(
        remaining,
        vec![open.job_id.clone(), recent.job_id.clone()],
        "open work and terminal work inside retention must survive cleanup"
    );
}

#[tokio::test]
async fn dispatch_targets_cache_hits_within_ttl_and_expires() {
    let ctx = setup_sqlite_storage("dispatch-targets-cache").await;
    let device_key = "dispatch-targets-cache-device-key";
    let token = "android-token-cache-hit-0000000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "cache-test",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("first fetch should succeed");
    assert_eq!(first.len(), 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("DELETE FROM channel_subscriptions WHERE channel_id = ?")
        .bind(&channel_id[..])
        .execute(&mut conn)
        .await
        .expect("direct delete should succeed");

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("cached fetch should succeed");
    assert_eq!(second.len(), 1);

    sleep(Duration::from_millis(2300)).await;

    let third = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("post-ttl fetch should succeed");
    assert_eq!(third.len(), 0);
}

#[tokio::test]
async fn dispatch_targets_cache_invalidates_on_unsubscribe() {
    let ctx = setup_sqlite_storage("dispatch-targets-invalidate").await;
    let device_key = "dispatch-targets-invalidate-device-key";
    let token = "android-token-cache-invalidate-000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "cache-invalidate",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let effective_at = chrono::Utc::now().timestamp_millis();

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("first fetch should succeed");
    assert_eq!(first.len(), 1);

    let removed = ctx
        .storage
        .unsubscribe_channel_for_device_key(channel_id, device_key)
        .await
        .expect("unsubscribe should succeed");
    assert!(removed);

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("post-invalidation fetch should succeed");
    assert_eq!(second.len(), 0);
}

#[tokio::test]
async fn dispatch_targets_cache_invalidates_on_device_route_update() {
    let ctx = setup_sqlite_storage("dispatch-targets-route-update-invalidate").await;
    let device_key = "dispatch-targets-route-update-device-key";
    let old_token = "android-token-route-update-old-000000000000000001";
    let new_token = "android-token-route-update-new-000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        old_token,
        "route-update-invalidate",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let effective_at = chrono::Utc::now().timestamp_millis();

    let first = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("first fetch should succeed");
    assert_eq!(first.len(), 1);
    match &first[0] {
        DispatchTarget::Provider { provider_token, .. } => {
            assert_eq!(provider_token, old_token);
        }
        other => panic!("expected provider target before route update, got {other:?}"),
    }

    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(new_token.to_string()),
            updated_at: effective_at + 1,
        })
        .await
        .expect("route update should succeed");

    let second = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("post-route-update fetch should succeed");
    assert_eq!(second.len(), 1);
    match &second[0] {
        DispatchTarget::Provider { provider_token, .. } => {
            assert_eq!(provider_token, new_token);
        }
        other => panic!("expected provider target after route update, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_subscriptions_can_be_managed_by_device_key() {
    let ctx = setup_sqlite_storage("provider-subscriptions-device-key").await;
    let device_key = "provider-subscriptions-device-key";
    let token = "android-token-device-key-management-000000000000001";
    seed_provider_route(
        &ctx.storage,
        device_key,
        Platform::ANDROID,
        token,
        chrono::Utc::now().timestamp_millis(),
    )
    .await;

    let subscribe = ctx
        .storage
        .subscribe_channel_for_device_key(
            None,
            Some("device-key-management"),
            "pw123456",
            device_key,
            token,
            Platform::ANDROID,
        )
        .await
        .expect("device-key subscribe should succeed");

    let channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(device_key)
        .await
        .expect("list subscribed channels by device key should succeed");
    assert_eq!(channels, vec![subscribe.channel_id]);

    let removed = ctx
        .storage
        .unsubscribe_channel_for_device_key(subscribe.channel_id, device_key)
        .await
        .expect("device-key unsubscribe should succeed");
    assert!(removed);

    let channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(device_key)
        .await
        .expect("list subscribed channels by device key should succeed");
    assert!(channels.is_empty());
}

#[tokio::test]
async fn channel_password_legacy_argon2id_hash_is_upgraded_to_blake3_after_successful_verify() {
    let ctx = setup_sqlite_storage("channel-password-upgrade").await;
    let channel_id = [7u8; 16];
    let alias = "legacy-password-channel";
    let password = "pw123456";
    let legacy_hash = hash_channel_password_argon2(password).expect("legacy argon2 hash");

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&channel_id[..])
    .bind(&legacy_hash)
    .bind(alias)
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("insert channel should succeed");
    ctx.storage.reset_channel_password_kdf_runs();

    const REQUESTS: usize = 600;
    let start = Arc::new(tokio::sync::Barrier::new(REQUESTS + 1));
    let mut checks = tokio::task::JoinSet::new();
    for _ in 0..REQUESTS {
        let storage = ctx.storage.clone();
        let start = Arc::clone(&start);
        checks.spawn(async move {
            start.wait().await;
            storage
                .channel_info_with_password(channel_id, password)
                .await
        });
    }
    start.wait().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(check) = checks.join_next().await {
            let info = check
                .expect("legacy verification task should join")
                .expect("legacy verification should succeed")
                .expect("channel must exist");
            assert_eq!(info.alias, alias);
            assert!(channel_password_uses_current_scheme(&info.password_hash));
        }
    })
    .await
    .expect("legacy Argon2 burst should migrate promptly");

    let upgraded_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("query password hash should succeed");
    assert!(channel_password_uses_current_scheme(&upgraded_hash));

    let cached = ctx
        .storage
        .channel_info_with_password(channel_id, password)
        .await
        .expect("cached channel_info_with_password should succeed")
        .expect("channel should stay cached");
    assert_eq!(cached.alias, alias);
    assert_eq!(cached.password_hash, upgraded_hash);
    assert_eq!(
        ctx.storage.channel_password_kdf_runs(),
        1,
        "legacy Argon2 verification should be the only KDF work"
    );
    let snapshot = ctx.storage.cache_memory_snapshot();
    assert_eq!(snapshot.channel_info_cache_entries, 1);
    assert!(snapshot.channel_info_password_hash_bytes >= upgraded_hash.len());
}

#[tokio::test]
async fn legacy_argon2id_failures_are_not_cached_or_migrated() {
    let ctx = setup_sqlite_storage("channel-password-legacy-failure").await;
    let channel_id = [9u8; 16];
    let legacy_input = "legacy-input";
    let legacy_hash = hash_channel_password_argon2(legacy_input).expect("legacy argon2 fixture");

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&channel_id[..])
    .bind(&legacy_hash)
    .bind("legacy-failure-channel")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("insert legacy channel should succeed");
    ctx.storage.reset_channel_password_kdf_runs();

    for _ in 0..2 {
        assert!(matches!(
            ctx.storage
                .channel_info_with_password(channel_id, "incorrect-input")
                .await,
            Err(StoreError::ChannelPasswordMismatch)
        ));
    }
    assert_eq!(ctx.storage.channel_password_kdf_runs(), 2);

    let stored: String =
        sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("query legacy channel hash should succeed");
    assert_eq!(stored, legacy_hash);
    assert!(!channel_password_uses_current_scheme(&stored));
}

#[tokio::test]
async fn cancelling_legacy_argon2id_leader_wakes_waiters_and_allows_retry() {
    let ctx = setup_sqlite_storage("channel-password-leader-cancel").await;
    let channel_id = [10u8; 16];
    let legacy_input = "legacy-cancel-input";
    let legacy_hash = hash_channel_password_argon2(legacy_input).expect("legacy argon2 fixture");

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&channel_id[..])
    .bind(&legacy_hash)
    .bind("legacy-cancel-channel")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("insert legacy channel should succeed");
    ctx.storage.reset_channel_password_kdf_runs();

    let leader_storage = ctx.storage.clone();
    let leader = tokio::spawn(async move {
        leader_storage
            .channel_info_with_password(channel_id, legacy_input)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while ctx.storage.channel_password_kdf_runs() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("legacy leader should enter Argon2 verification");

    let waiter_storage = ctx.storage.clone();
    let waiter = tokio::spawn(async move {
        waiter_storage
            .channel_info_with_password(channel_id, legacy_input)
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    leader.abort();
    assert!(
        leader
            .await
            .expect_err("leader should be cancelled")
            .is_cancelled()
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter must be woken")
            .expect("waiter task should join"),
        Err(StoreError::PasswordKdfBusy)
    ));

    let recovered = ctx
        .storage
        .channel_info_with_password(channel_id, legacy_input)
        .await
        .expect("retry after cancellation should succeed")
        .expect("channel should exist");
    assert!(channel_password_uses_current_scheme(
        &recovered.password_hash
    ));
    assert_eq!(ctx.storage.channel_password_kdf_runs(), 2);
}

#[tokio::test]
async fn failed_legacy_argon2id_database_upgrade_is_not_cached_and_retries() {
    let ctx = setup_sqlite_storage("channel-password-upgrade-failure").await;
    let channel_id = [11u8; 16];
    let legacy_input = "legacy-upgrade-retry-input";
    let legacy_hash = hash_channel_password_argon2(legacy_input).expect("legacy argon2 fixture");

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&channel_id[..])
    .bind(&legacy_hash)
    .bind("legacy-upgrade-failure-channel")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("insert legacy channel should succeed");
    sqlx::query(
        "CREATE TRIGGER reject_channel_hash_upgrade \
         BEFORE UPDATE OF password_hash ON channels \
         BEGIN SELECT RAISE(ABORT, 'injected upgrade failure'); END",
    )
    .execute(&mut conn)
    .await
    .expect("create failure trigger should succeed");
    ctx.storage.reset_channel_password_kdf_runs();

    assert!(
        ctx.storage
            .channel_info_with_password(channel_id, legacy_input)
            .await
            .is_err()
    );
    assert_eq!(ctx.storage.channel_password_kdf_runs(), 1);
    let unchanged: String =
        sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id = ?")
            .bind(&channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("query legacy hash should succeed");
    assert_eq!(unchanged, legacy_hash);

    sqlx::query("DROP TRIGGER reject_channel_hash_upgrade")
        .execute(&mut conn)
        .await
        .expect("drop failure trigger should succeed");
    let recovered = ctx
        .storage
        .channel_info_with_password(channel_id, legacy_input)
        .await
        .expect("retry after database recovery should succeed")
        .expect("channel should exist");
    assert!(channel_password_uses_current_scheme(
        &recovered.password_hash
    ));
    assert_eq!(ctx.storage.channel_password_kdf_runs(), 2);
}

#[tokio::test]
async fn six_hundred_current_blake3_password_checks_bypass_the_legacy_kdf_gate() {
    const REQUESTS: usize = 600;
    let ctx = setup_sqlite_storage("channel-auth-singleflight-600").await;
    let input = "singleflight-auth-input-600";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "channel-auth-singleflight-device",
        "channel-auth-singleflight-token-000000000000000000000001",
        "channel-auth-singleflight",
        input,
        Platform::ANDROID,
    )
    .await;
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let stored_before: String =
        sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id = ?")
            .bind(&subscribe.channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("query initial channel hash should succeed");
    assert!(channel_password_uses_current_scheme(&stored_before));
    ctx.storage.reset_channel_password_kdf_runs();

    let start = Arc::new(tokio::sync::Barrier::new(REQUESTS + 1));
    let mut checks = tokio::task::JoinSet::new();
    for _ in 0..REQUESTS {
        let storage = ctx.storage.clone();
        let start = Arc::clone(&start);
        checks.spawn(async move {
            start.wait().await;
            storage
                .channel_info_with_password(subscribe.channel_id, input)
                .await
        });
    }
    start.wait().await;

    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(check) = checks.join_next().await {
            assert!(
                check
                    .expect("password check task should join")
                    .expect("valid burst must not overload")
                    .is_some()
            );
        }
    })
    .await
    .expect("600-request password burst should complete promptly");
    assert_eq!(
        ctx.storage.channel_password_kdf_runs(),
        0,
        "current salted BLAKE3 checks must not enter the legacy Argon2 gate"
    );

    for _ in 0..REQUESTS {
        assert!(
            ctx.storage
                .channel_info_with_password(subscribe.channel_id, input)
                .await
                .expect("current salted BLAKE3 should serve the follow-up burst")
                .is_some()
        );
    }
    assert_eq!(ctx.storage.channel_password_kdf_runs(), 0);
    let stored_after: String =
        sqlx::query_scalar("SELECT password_hash FROM channels WHERE channel_id = ?")
            .bind(&subscribe.channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("query final channel hash should succeed");
    assert_eq!(stored_after, stored_before);
}

#[tokio::test]
async fn current_blake3_password_failures_bypass_the_legacy_kdf_gate() {
    let ctx = setup_sqlite_storage("channel-auth-error-not-cached").await;
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "channel-auth-error-device",
        "channel-auth-error-token-000000000000000000000000000001",
        "channel-auth-error",
        "correct-auth-input",
        Platform::ANDROID,
    )
    .await;
    ctx.storage.reset_channel_password_kdf_runs();

    for _ in 0..2 {
        assert!(matches!(
            ctx.storage
                .channel_info_with_password(subscribe.channel_id, "wrong-auth-input")
                .await,
            Err(StoreError::ChannelPasswordMismatch)
        ));
    }
    assert_eq!(ctx.storage.channel_password_kdf_runs(), 0);
}

#[tokio::test]
async fn dispatch_targets_follow_current_route_when_present() {
    let ctx = setup_sqlite_storage("dispatch-targets-current-route").await;
    let token = "android-token-current-route-000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "dispatch-targets-current-route-device-key",
        token,
        "current-route",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "dispatch-targets-current-route-device-key";
    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, token, now).await;
    let effective_at = now + 100;

    let initial = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, effective_at)
        .await
        .expect("initial fetch should succeed");
    assert_eq!(initial.len(), 1);

    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    // Membership should follow the current route and become private delivery.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'private', provider_token = NULL, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(now + 2)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route update to private should succeed");
    let filtered_private = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 101)
        .await
        .expect("fetch with private current route should succeed");
    assert_eq!(filtered_private.len(), 1);
    match &filtered_private[0] {
        DispatchTarget::Private {
            device_id: private_device_id,
            device_key: private_device_key,
            platform,
        } => {
            assert_eq!(private_device_id, &device_id);
            assert_eq!(private_device_key.as_deref(), Some(device_key));
            assert_eq!(*platform, Platform::ANDROID);
        }
        other => panic!("expected private target after route switch, got {other:?}"),
    }

    // Current route says provider with a new token, so dispatch should follow the new token.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'fcm', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind("android-token-current-route-mismatch")
    .bind(now + 4)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route update to mismatched provider token should succeed");
    let filtered_token_mismatch = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 102)
        .await
        .expect("fetch with mismatched provider token should succeed");
    assert_eq!(filtered_token_mismatch.len(), 1);
    match &filtered_token_mismatch[0] {
        DispatchTarget::Provider { provider_token, .. } => {
            assert_eq!(provider_token, "android-token-current-route-mismatch");
        }
        other => panic!("expected provider target after route token update, got {other:?}"),
    }

    // Route snapshot can switch back again and dispatch should continue following devices.
    sqlx::query(
        "UPDATE devices \
         SET channel_type = 'fcm', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(token)
    .bind(now + 6)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route update to matching provider token should succeed");
    let restored = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 103)
        .await
        .expect("fetch with matching current route should succeed");
    assert_eq!(restored.len(), 1);
}

#[tokio::test]
async fn provider_route_fence_rejects_superseded_token_revision() {
    let ctx = setup_sqlite_storage("provider-route-fence").await;
    let device_key = "provider-route-fence-device-key";
    let old_token = "android-token-route-fence-old-00000000000000000001";
    let new_token = "android-token-route-fence-new-00000000000000000001";
    let now = chrono::Utc::now().timestamp_millis();
    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, old_token, now).await;

    assert!(
        ctx.storage
            .provider_route_is_current(
                device_key,
                Platform::ANDROID,
                RouteChannelType::Fcm,
                old_token,
                now,
            )
            .await
            .expect("current route check should succeed")
    );

    seed_provider_route(
        &ctx.storage,
        device_key,
        Platform::ANDROID,
        new_token,
        now + 1,
    )
    .await;
    assert!(
        !ctx.storage
            .provider_route_is_current(
                device_key,
                Platform::ANDROID,
                RouteChannelType::Fcm,
                old_token,
                now,
            )
            .await
            .expect("stale route check should succeed")
    );
}

#[tokio::test]
async fn provider_route_fence_accepts_same_token_refresh_generation() {
    let ctx = setup_sqlite_storage("provider-route-fence-same-token-refresh").await;
    let device_key = "provider-route-fence-same-token-device-key";
    let token = "android-token-route-fence-same-00000000000000000001";
    let now = chrono::Utc::now().timestamp_millis();
    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, token, now).await;
    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, token, now + 1).await;

    assert!(
        ctx.storage
            .provider_route_is_current(
                device_key,
                Platform::ANDROID,
                RouteChannelType::Fcm,
                token,
                now,
            )
            .await
            .expect("same-token refreshed route check should succeed"),
        "refreshing the same provider token must not suppress an already durable send"
    );
}

#[tokio::test]
async fn dispatch_targets_skip_mqtt_provider_route_rows() {
    let ctx = setup_sqlite_storage("dispatch-targets-skip-mqtt-provider-route").await;
    let token = "android-token-skip-mqtt-provider-route-000000000001";
    let device_key = "dispatch-targets-skip-mqtt-provider-route-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "skip-mqtt-provider-route",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    sqlx::query(
        "UPDATE devices \
         SET platform = 'mqtt', platform_code = ?, channel_type = 'apns', provider_token = ?, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(Platform::MQTT.to_byte() as i64)
    .bind("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    .bind(now + 1)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("direct mqtt provider route mutation should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 2)
        .await
        .expect("dispatch target fetch should succeed");
    assert!(
        targets.is_empty(),
        "mqtt provider route rows must not become provider dispatch targets"
    );
}

#[tokio::test]
async fn dispatch_targets_include_mqtt_private_platform() {
    let ctx = setup_sqlite_storage("dispatch-targets-mqtt-private-platform").await;
    let token = "android-token-mqtt-private-platform-00000000000001";
    let device_key = "dispatch-targets-mqtt-private-platform-device";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token,
        "mqtt-private-platform",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");

    sqlx::query(
        "UPDATE devices \
         SET platform = 'mqtt', platform_code = ?, channel_type = 'private', provider_token = NULL, route_updated_at = ? \
         WHERE device_id = ?",
    )
    .bind(Platform::MQTT.to_byte() as i64)
    .bind(now + 1)
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("direct mqtt private route mutation should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 2)
        .await
        .expect("dispatch target fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Private {
            device_id: target_device_id,
            device_key: target_device_key,
            platform,
        } => {
            assert_eq!(target_device_id, &device_id);
            assert_eq!(target_device_key.as_deref(), Some(device_key));
            assert_eq!(*platform, Platform::MQTT);
        }
        other => panic!("expected mqtt private target, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_targets_drop_provider_rows_without_current_route() {
    let ctx = setup_sqlite_storage("dispatch-targets-no-current-route").await;
    let token = "android-token-no-current-route-0000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "dispatch-targets-no-current-route-device-key",
        token,
        "route-missing",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "dispatch-targets-no-current-route-device-key";
    let device_id = derive_private_device_id(device_key);

    seed_provider_route(&ctx.storage, device_key, Platform::ANDROID, token, now).await;
    let with_snapshot = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 100)
        .await
        .expect("fetch with current route should succeed");
    assert_eq!(with_snapshot.len(), 1);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "UPDATE devices \
         SET route_updated_at = NULL \
         WHERE device_id = ?",
    )
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("route_updated_at reset should succeed");

    let without_snapshot = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 101)
        .await
        .expect("fetch without current route should succeed");
    assert!(
        without_snapshot.is_empty(),
        "provider rows without current route must be filtered out"
    );
}

#[tokio::test]
async fn dispatch_targets_use_route_device_key_as_single_source() {
    let ctx = setup_sqlite_storage("dispatch-targets-route-device-key-source").await;
    let token = "android-token-route-device-key-source-000000001";
    let canonical_device_key = "route-device-key-source";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        canonical_device_key,
        token,
        "route-device-key-source",
        "pw123456",
        Platform::ANDROID,
    )
    .await;

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(
            subscribe.channel_id,
            chrono::Utc::now().timestamp_millis() + 1,
        )
        .await
        .expect("fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider { device_key, .. } => {
            assert_eq!(device_key.as_str(), canonical_device_key);
        }
        other => panic!("expected provider target, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_targets_dedupe_duplicate_provider_token_routes() {
    let ctx = setup_sqlite_storage("dispatch-targets-dedupe-provider-token").await;
    let token = "android-token-dedupe-provider-token-0000000001";
    let canonical_device_key = "dispatch-targets-dedupe-provider-token-current";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        canonical_device_key,
        token,
        "route-token-dedupe",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let canonical_updated_at = chrono::Utc::now().timestamp_millis();
    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: canonical_device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(token.to_string()),
            updated_at: canonical_updated_at,
        })
        .await
        .expect("canonical route refresh should succeed");

    let stale_route = DeviceRouteRecordRow {
        device_key: "dispatch-targets-dedupe-provider-token-stale".to_string(),
        platform: Platform::ANDROID.name().to_string(),
        channel_type: Platform::ANDROID.channel_type().to_string(),
        provider_token: Some(token.to_string()),
        updated_at: canonical_updated_at - 1_000,
    }
    .persistence_values()
    .expect("stale route should derive persistence values");
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO devices \
         (device_id, token_raw, platform_code, device_key, platform, channel_type, provider_token, route_updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(stale_route.device_id.as_slice())
    .bind(stale_route.token_raw.as_slice())
    .bind(stale_route.platform_code)
    .bind(&stale_route.device_key)
    .bind(&stale_route.platform)
    .bind(&stale_route.channel_type)
    .bind(stale_route.provider_token.as_deref())
    .bind(stale_route.updated_at)
    .execute(&mut conn)
    .await
    .expect("stale duplicate route insert should succeed");
    sqlx::query(
        "INSERT INTO channel_subscriptions (channel_id, device_id, status, created_at, updated_at) \
         VALUES (?, ?, 'active', ?, ?)",
    )
    .bind(&subscribe.channel_id[..])
    .bind(stale_route.device_id.as_slice())
    .bind(stale_route.updated_at)
    .bind(stale_route.updated_at)
    .execute(&mut conn)
    .await
    .expect("stale duplicate subscription insert should succeed");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("dispatch target fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider {
            provider_token,
            device_key,
            ..
        } => {
            assert_eq!(provider_token, token);
            assert_eq!(device_key, canonical_device_key);
        }
        other => panic!("expected provider target after dedupe, got {other:?}"),
    }
}

#[tokio::test]
async fn provider_pull_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-pull-lifecycle").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "provider-pull-activity-device";
    let provider_token = "android-token-provider-pull-activity-000000000000000001";
    let device_id = derive_private_device_id(device_key);
    let stale_activity = now - 120_000;
    ctx.storage
        .upsert_device_route(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(provider_token.to_string()),
            updated_at: stale_activity,
        })
        .await
        .expect("device route should be inserted");
    let delivery_id = "delivery-provider-lifecycle-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3, 4].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            provider_token,
        )
        .await
        .expect("enqueue should succeed");

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("pull should succeed");
    assert!(pulled.is_some());
    assert_eq!(
        pulled.expect("item should exist").delivery_id,
        delivery_id.to_string()
    );
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let refreshed_at: i64 =
        sqlx::query_scalar("SELECT route_updated_at FROM devices WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("route activity should be queryable");
    assert_eq!(refreshed_at, now + 1);

    let pulled_again = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 2)
        .await
        .expect("second pull should succeed");
    assert!(pulled_again.is_none());
}

#[tokio::test]
async fn consumed_provider_delivery_tombstone_blocks_frozen_replay() {
    let ctx = setup_sqlite_storage("provider-pull-terminal-replay").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [71; 16];
    let delivery_id = "provider-pull-terminal-replay-delivery";
    let message = PrivateMessage {
        payload: vec![4, 3, 2, 1].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
    };

    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "provider-terminal-replay-token",
        )
        .await
        .expect("initial provider delivery should enqueue");
    assert!(
        ctx.storage
            .pull_provider_item(device_id, delivery_id, now + 1)
            .await
            .expect("initial provider delivery should pull")
            .is_some()
    );

    // Simulate the frozen manifest replaying the same provider-pull target.
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "provider-terminal-replay-token",
        )
        .await
        .expect("idempotent replay should not fail");
    assert!(
        ctx.storage
            .peek_provider_item(device_id, delivery_id, now + 2)
            .await
            .expect("replayed provider row should be checked")
            .is_none(),
        "a consumed provider target must never be recreated"
    );
    let tombstone = ctx
        .storage
        .load_private_outbox_entry(device_id, delivery_id)
        .await
        .expect("tombstone lookup should succeed")
        .expect("consumption must leave a durable tombstone");
    assert_eq!(tombstone.status, OUTBOX_STATUS_ACKED);

    ctx.storage
        .run_maintenance_cleanup(
            now + (35 * 24 + 12) * 60 * 60 * 1_000,
            MaintenanceCleanupConfig {
                private_stale_outbox_ttl_secs: 30 * 24 * 60 * 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("35.5-day maintenance should succeed");
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("35.5-day tombstone lookup should succeed")
            .is_some(),
        "ACK tombstone must outlive the 35-day frozen manifest"
    );
    ctx.storage
        .run_maintenance_cleanup(
            now + 37 * 24 * 60 * 60 * 1_000,
            MaintenanceCleanupConfig {
                private_stale_outbox_ttl_secs: 30 * 24 * 60 * 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("37-day maintenance should succeed");
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("37-day tombstone lookup should succeed")
            .is_none(),
        "tombstone storage must eventually be reclaimed"
    );
}

#[tokio::test]
async fn acknowledged_private_delivery_is_not_demoted_by_replay() {
    let ctx = setup_sqlite_storage("private-terminal-replay").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [72; 16];
    let delivery_id = "private-terminal-replay-delivery";
    let pending = PrivateOutboxEntry {
        delivery_id: delivery_id.to_string(),
        status: OUTBOX_STATUS_PENDING.to_string(),
        attempts: 0,
        occurred_at: now,
        created_at: now,
        claimed_at: None,
        claimed_by: None,
        claim_generation: 0,
        first_sent_at: None,
        last_attempt_at: None,
        acked_at: None,
        fallback_sent_at: None,
        next_attempt_at: now,
        last_error_code: None,
        last_error_detail: None,
        updated_at: now,
    };
    ctx.storage
        .enqueue_private_outbox(device_id, &pending)
        .await
        .expect("private delivery should enqueue");
    assert!(
        ctx.storage
            .ack_private_delivery(device_id, delivery_id)
            .await
            .expect("private acknowledgement should succeed")
    );

    ctx.storage
        .enqueue_private_outbox(device_id, &pending)
        .await
        .expect("frozen replay should be idempotent");
    assert!(
        ctx.storage
            .list_private_outbox(device_id, 10)
            .await
            .expect("active outbox should be readable")
            .is_empty(),
        "replay must not demote an ACK tombstone to pending"
    );
    assert_eq!(
        ctx.storage
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("tombstone lookup should succeed")
            .expect("ACK tombstone should remain")
            .status,
        OUTBOX_STATUS_ACKED
    );
}

#[tokio::test]
async fn private_payload_is_immutable_for_a_reused_delivery_id() {
    let ctx = setup_sqlite_storage("private-payload-immutable").await;
    let now = chrono::Utc::now().timestamp_millis();
    let delivery_id = "private-payload-immutable-delivery";
    let original = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 60_000,
    };
    let conflicting = PrivateMessage {
        payload: vec![9, 8, 7, 6].into(),
        size: 4,
        sent_at: now + 1,
        expires_at: now + 120_000,
    };

    ctx.storage
        .insert_private_message(delivery_id, &original)
        .await
        .expect("original payload should persist");
    ctx.storage
        .insert_private_message(delivery_id, &conflicting)
        .await
        .expect("idempotent replay should not fail");

    let stored = ctx
        .storage
        .load_private_message(delivery_id)
        .await
        .expect("payload lookup should succeed")
        .expect("original payload should remain");
    assert_eq!(stored.payload.as_ref(), original.payload.as_ref());
    assert_eq!(stored.sent_at, original.sent_at);
    assert_eq!(stored.expires_at, original.expires_at);
}

#[tokio::test]
async fn provider_pull_uses_legacy_queue_payload_when_shared_payload_missing() {
    let ctx = setup_sqlite_storage("provider-pull-legacy-queue-payload").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [17; 16];
    let delivery_id = "delivery-provider-legacy-queue-001";
    let legacy_payload = vec![0xAB, 0xCD, 0xEF];

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO provider_pull_queue \
         (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(delivery_id)
    .bind(&legacy_payload)
    .bind(legacy_payload.len() as i64)
    .bind(now)
    .bind(now + 300_000)
    .bind(Platform::ANDROID.name())
    .bind("fcm-token-legacy-001")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("legacy provider pull row insert should succeed");
    drop(conn);

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("pull should succeed")
        .expect("item should exist");
    assert_eq!(pulled.payload, legacy_payload.into());
}

#[tokio::test]
async fn provider_ack_lifecycle_works() {
    let ctx = setup_sqlite_storage("provider-ack-lifecycle").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];
    let delivery_id = "delivery-provider-ack-001";
    let message = PrivateMessage {
        payload: vec![8, 6, 4, 2].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "fcm-token-ack-001",
        )
        .await
        .expect("enqueue should succeed");

    let acked = ctx
        .storage
        .ack_provider_item(device_id, delivery_id, now + 1)
        .await
        .expect("ack should succeed");
    assert!(acked.is_some());
    assert_eq!(
        acked.expect("item should exist").delivery_id,
        delivery_id.to_string()
    );

    let acked_again = ctx
        .storage
        .ack_provider_item(device_id, delivery_id, now + 2)
        .await
        .expect("second ack should succeed");
    assert!(acked_again.is_none());
}

#[tokio::test]
async fn provider_pull_items_limit_and_order_works() {
    let ctx = setup_sqlite_storage("provider-pull-limit-order").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [5; 16];
    let ids = [
        "delivery-provider-batch-001",
        "delivery-provider-batch-002",
        "delivery-provider-batch-003",
    ];
    for (index, delivery_id) in ids.iter().enumerate() {
        let message = PrivateMessage {
            payload: vec![index as u8].into(),
            size: 1,
            sent_at: now + index as i64,
            expires_at: now + 600_000,
        };
        ctx.storage
            .enqueue_provider_pull_item(
                device_id,
                delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-batch-001",
            )
            .await
            .expect("enqueue should succeed");
    }

    let first_batch = ctx
        .storage
        .pull_provider_items(device_id, now + 1, 2)
        .await
        .expect("first pull batch should succeed");
    assert_eq!(first_batch.len(), 2);
    assert_eq!(first_batch[0].delivery_id, ids[0]);
    assert_eq!(first_batch[1].delivery_id, ids[1]);

    let second_batch = ctx
        .storage
        .pull_provider_items(device_id, now + 2, 2)
        .await
        .expect("second pull batch should succeed");
    assert_eq!(second_batch.len(), 1);
    assert_eq!(second_batch[0].delivery_id, ids[2]);
}

#[tokio::test]
async fn provider_pull_drains_queue_and_orphan_payloads_on_read() {
    let ctx = setup_sqlite_storage("provider-pull-drains-orphan-payloads").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];
    let delivery_id = "delivery-provider-drain-orphan-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 600_000,
    };

    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("insert shared private payload should succeed");

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO provider_pull_queue \
         (device_id, delivery_id, payload_blob, payload_size, sent_at, expires_at, platform, provider_token, created_at, updated_at) \
         VALUES (?, ?, X'', 0, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(delivery_id)
    .bind(message.sent_at)
    .bind(message.expires_at)
    .bind(Platform::ANDROID.name())
    .bind("fcm-token-provider-drain-orphan-001")
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("provider pull queue insert should succeed");
    let payload_count_before: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("private payload count before pull should succeed");
    assert_eq!(payload_count_before, 1);
    drop(conn);

    let pulled = ctx
        .storage
        .pull_provider_items(device_id, now + 1, 10)
        .await
        .expect("provider pull should succeed");
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].delivery_id, delivery_id);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let queue_count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("provider queue count after pull should succeed");
    let payload_count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("private payload count after pull should succeed");
    assert_eq!(queue_count_after, 0);
    assert_eq!(payload_count_after, 0);
}

#[tokio::test]
async fn migrate_provider_pending_to_private_outbox_rejects_partial_migration() {
    let ctx = setup_sqlite_storage("provider-to-private-migration-capacity").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "provider-to-private-capacity-device";
    let device_id = derive_private_device_id(device_key);
    let provider_token = "fcm-token-migration-capacity-001";
    seed_provider_route(
        &ctx.storage,
        device_key,
        Platform::ANDROID,
        provider_token,
        now,
    )
    .await;

    let existing_delivery = "delivery-private-existing-capacity-001";
    let existing_message = PrivateMessage {
        payload: vec![9, 9, 9].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 600_000,
    };
    ctx.storage
        .insert_private_message(existing_delivery, &existing_message)
        .await
        .expect("insert existing private message should succeed");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: existing_delivery.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now,
            },
        )
        .await
        .expect("enqueue existing private outbox should succeed");

    let provider_deliveries = [
        "delivery-provider-capacity-001",
        "delivery-provider-capacity-002",
        "delivery-provider-capacity-003",
    ];
    for (index, delivery_id) in provider_deliveries.iter().enumerate() {
        let message = PrivateMessage {
            payload: vec![index as u8, 1, 2].into(),
            size: 3,
            sent_at: now + index as i64,
            expires_at: now + 600_000,
        };
        ctx.storage
            .enqueue_provider_pull_item(
                device_id,
                delivery_id,
                &message,
                Platform::ANDROID,
                provider_token,
            )
            .await
            .expect("enqueue provider pull item should succeed");
    }

    let private_pending_before = ctx
        .storage
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private pending count before migration should succeed");
    assert_eq!(private_pending_before, 1);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let provider_pending_before: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("provider pending count before migration should succeed");
    assert_eq!(provider_pending_before, 3);
    drop(conn);

    let err = ctx
        .storage
        .transition_device_route(
            &DeviceRouteRecordRow {
                device_key: device_key.to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: "private".to_string(),
                provider_token: None,
                updated_at: now + 1,
            },
            RouteChannelType::Fcm,
            30,
            2,
        )
        .await
        .expect_err("provider->private migration must not partially switch at capacity");
    assert!(
        matches!(
            err,
            StoreError::RouteMigrationCapacityExceeded {
                pending: 3,
                capacity: 1
            }
        ),
        "unexpected capacity error: {err:?}"
    );

    let private_pending = ctx
        .storage
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private pending count should succeed");
    assert_eq!(private_pending, 1);

    let mut migrated_provider_count = 0usize;
    for delivery_id in provider_deliveries {
        let exists = ctx
            .storage
            .load_private_outbox_entry(device_id, delivery_id)
            .await
            .expect("private outbox lookup should succeed")
            .is_some();
        if exists {
            migrated_provider_count = migrated_provider_count.saturating_add(1);
        }
    }
    assert_eq!(migrated_provider_count, 0);

    let route = ctx
        .storage
        .load_device_routes()
        .await
        .expect("route should remain queryable")
        .into_iter()
        .find(|route| route.device_key == device_key)
        .expect("route should remain present");
    assert_eq!(
        route.channel_type,
        Platform::ANDROID.channel_type(),
        "failed migration must not commit the private route"
    );

    let remaining_provider_items = ctx
        .storage
        .pull_provider_items(device_id, now + 100_000, 10)
        .await
        .expect("provider pull remaining items should succeed");
    assert_eq!(
        remaining_provider_items.len(),
        3,
        "provider queue must remain intact when the migration cannot fit atomically"
    );
}

#[tokio::test]
async fn stale_route_transition_is_rejected_by_database_revision_cas() {
    let ctx = setup_sqlite_storage("route-transition-stale-cas").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "route-transition-stale-cas-device";
    let provider_token = "route-transition-stale-cas-provider-token";
    seed_provider_route(
        &ctx.storage,
        device_key,
        Platform::ANDROID,
        provider_token,
        now,
    )
    .await;

    let migrated = ctx
        .storage
        .transition_device_route(
            &DeviceRouteRecordRow {
                device_key: device_key.to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: "private".to_string(),
                provider_token: None,
                updated_at: now + 10,
            },
            RouteChannelType::Private,
            30,
            16,
        )
        .await
        .expect("newer private transition should succeed");
    assert_eq!(migrated, 0);

    let stale = ctx
        .storage
        .transition_device_route(
            &DeviceRouteRecordRow {
                device_key: device_key.to_string(),
                platform: Platform::ANDROID.name().to_string(),
                channel_type: Platform::ANDROID.channel_type().to_string(),
                provider_token: Some(provider_token.to_string()),
                updated_at: now + 5,
            },
            RouteChannelType::Fcm,
            30,
            16,
        )
        .await
        .expect("stale transition should be rejected without a storage error");
    assert_eq!(stale, 0);

    let route = ctx
        .storage
        .load_device_routes()
        .await
        .expect("route should be queryable")
        .into_iter()
        .find(|route| route.device_key == device_key)
        .expect("route should remain present");
    assert_eq!(route.channel_type, "private");
    let mut core_conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("core sqlite connection should succeed");
    let revision: i64 =
        sqlx::query_scalar("SELECT route_revision FROM devices WHERE device_key = ?")
            .bind(device_key)
            .fetch_one(&mut core_conn)
            .await
            .expect("route revision should be queryable");
    assert_eq!(
        revision, 2,
        "stale transition must not advance the revision"
    );
}

#[tokio::test]
async fn migrate_private_pending_to_provider_queue_batches_payloads_and_clears_outbox() {
    let ctx = setup_sqlite_storage("private-to-provider-migration-batch").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [6; 16];
    let provider_token = "fcm-token-private-to-provider-batch-001";
    let delivery_ids = [
        "delivery-private-to-provider-001",
        "delivery-private-to-provider-002",
        "delivery-private-to-provider-003",
    ];

    for (index, delivery_id) in delivery_ids.iter().enumerate() {
        let message = PrivateMessage {
            payload: vec![index as u8, 4, 5].into(),
            size: 3,
            sent_at: now + index as i64,
            expires_at: now + 600_000,
        };
        ctx.storage
            .insert_private_message(delivery_id, &message)
            .await
            .expect("private payload should be inserted");
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now + index as i64,
                    created_at: now + index as i64,
                    claimed_at: None,
                    claimed_by: None,
                    claim_generation: 0,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now,
                },
            )
            .await
            .expect("private outbox should be inserted");
    }

    let missing_delivery_id = "delivery-private-to-provider-missing-payload";
    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO private_outbox \
         (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
         VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(missing_delivery_id)
    .bind(OUTBOX_STATUS_PENDING)
    .bind(now + 10)
    .bind(now + 10)
    .bind(now)
    .bind(now)
    .execute(&mut conn)
    .await
    .expect("dangling private outbox should be inserted");
    drop(conn);

    let migrated = ctx
        .storage
        .migrate_private_pending_to_provider_queue(device_id, Platform::ANDROID, provider_token)
        .await
        .expect("private->provider migration should succeed");
    assert_eq!(migrated, delivery_ids.len());

    let private_pending = ctx
        .storage
        .count_private_outbox_for_device(device_id)
        .await
        .expect("private outbox count should succeed");
    assert_eq!(private_pending, 0);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let provider_pending: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ?")
            .bind(&device_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("provider pull count should be queryable");
    assert_eq!(provider_pending, delivery_ids.len() as i64);

    for delivery_id in delivery_ids {
        let payload_exists: i64 =
            sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
                .bind(delivery_id)
                .fetch_one(&mut conn)
                .await
                .expect("payload count should be queryable");
        assert_eq!(payload_exists, 1);
    }
    let missing_payload_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(missing_delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("missing payload count should be queryable");
    assert_eq!(missing_payload_exists, 0);
}

#[tokio::test]
async fn private_payload_cleanup_keeps_referenced_and_drops_orphan() {
    let ctx = setup_sqlite_storage("private-payload-cleanup").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_a: DeviceId = [1; 16];
    let device_b: DeviceId = [2; 16];

    let message = PrivateMessage {
        payload: vec![9, 8, 7, 6].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
    };

    let shared_delivery_id = "delivery-private-shared-001";
    ctx.storage
        .insert_private_message(shared_delivery_id, &message)
        .await
        .expect("insert shared payload should succeed");

    let entry = PrivateOutboxEntry {
        delivery_id: shared_delivery_id.to_string(),
        status: OUTBOX_STATUS_PENDING.to_string(),
        attempts: 0,
        occurred_at: now,
        created_at: now,
        claimed_at: None,
        claimed_by: None,
        claim_generation: 0,
        first_sent_at: None,
        last_attempt_at: None,
        acked_at: None,
        fallback_sent_at: None,
        next_attempt_at: now,
        last_error_code: None,
        last_error_detail: None,
        updated_at: now,
    };
    ctx.storage
        .enqueue_private_outbox(device_a, &entry)
        .await
        .expect("enqueue entry a should succeed");
    ctx.storage
        .enqueue_private_outbox(device_b, &entry)
        .await
        .expect("enqueue entry b should succeed");

    ctx.storage
        .ack_private_delivery(device_a, shared_delivery_id)
        .await
        .expect("ack entry a should succeed");
    let shared_still_exists = ctx
        .storage
        .load_private_message(shared_delivery_id)
        .await
        .expect("shared payload lookup should succeed");
    assert!(shared_still_exists.is_some());

    ctx.storage
        .ack_private_delivery(device_b, shared_delivery_id)
        .await
        .expect("ack entry b should succeed");
    let shared_after_all_acked = ctx
        .storage
        .load_private_message(shared_delivery_id)
        .await
        .expect("shared payload second lookup should succeed");
    assert!(shared_after_all_acked.is_none());
}

#[tokio::test]
async fn private_outbox_claim_lease_blocks_duplicate_active_claims() {
    let ctx = setup_sqlite_storage("private-outbox-claim-lease").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [42; 16];
    let delivery_id = "delivery-claim-lease-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("private message should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now,
            },
        )
        .await
        .expect("private outbox should be inserted");

    let first_claim = ctx
        .storage
        .claim_private_outbox_due_for_device(
            device_id,
            crate::delivery_core::store::delivery_queue::QueueClaimRequest::new(
                now,
                16,
                now + 30_000,
                crate::delivery_core::store::delivery_queue::QueueWorkerId::new("worker-a"),
            ),
        )
        .await
        .expect("first claim should succeed");
    assert_eq!(first_claim.len(), 1);
    assert_eq!(first_claim[0].claimed_by.as_deref(), Some("worker-a"));
    assert_eq!(first_claim[0].claim_generation, 1);

    let duplicate_claim = ctx
        .storage
        .claim_private_outbox_due_for_device(
            device_id,
            crate::delivery_core::store::delivery_queue::QueueClaimRequest::new(
                now + 1_000,
                16,
                now + 40_000,
                crate::delivery_core::store::delivery_queue::QueueWorkerId::new("worker-b"),
            ),
        )
        .await
        .expect("duplicate active claim should not fail");
    assert!(
        duplicate_claim.is_empty(),
        "active lease must prevent duplicate claim by another worker"
    );

    let expired_claim = ctx
        .storage
        .claim_private_outbox_due_for_device(
            device_id,
            crate::delivery_core::store::delivery_queue::QueueClaimRequest::new(
                now + 31_000,
                16,
                now + 60_000,
                crate::delivery_core::store::delivery_queue::QueueWorkerId::new("worker-b"),
            ),
        )
        .await
        .expect("expired lease claim should succeed");
    assert_eq!(expired_claim.len(), 1);
    assert_eq!(expired_claim[0].claimed_by.as_deref(), Some("worker-b"));
    assert_eq!(expired_claim[0].claimed_at, Some(now + 60_000));
    assert_eq!(expired_claim[0].claim_generation, 2);

    assert!(
        !ctx.storage
            .mark_private_fallback_sent_if_claimed(
                device_id,
                delivery_id,
                "worker-a",
                first_claim[0].claim_generation,
                now + 61_000,
            )
            .await
            .expect("stale settlement should be checked"),
        "a stale worker must not settle a newer claim generation"
    );
    assert!(
        ctx.storage
            .mark_private_fallback_sent_if_claimed(
                device_id,
                delivery_id,
                "worker-b",
                expired_claim[0].claim_generation,
                now + 61_000,
            )
            .await
            .expect("current settlement should be checked"),
        "the current worker and generation should settle the claim"
    );
}

#[tokio::test]
async fn concurrent_legacy_provider_pull_delivers_exactly_once() {
    let ctx = setup_sqlite_storage("provider-pull-concurrent-exactly-once").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [43; 16];
    let delivery_id = "provider-pull-concurrent-delivery";
    let message = PrivateMessage {
        payload: vec![7, 8, 9].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "provider-pull-concurrent-token",
        )
        .await
        .expect("provider item should be enqueued");

    let first_storage = ctx.storage.clone();
    let second_storage = ctx.storage.clone();
    let (first, second) = tokio::join!(
        first_storage.pull_provider_item(device_id, delivery_id, now + 1),
        second_storage.pull_provider_item(device_id, delivery_id, now + 1),
    );
    let delivered = [first, second]
        .into_iter()
        .map(|result| result.expect("concurrent pull should not fail"))
        .filter(Option::is_some)
        .count();
    assert_eq!(delivered, 1, "a legacy item must be consumed exactly once");
}

#[tokio::test]
async fn private_expired_cleanup_removes_expired_payloads_and_dangling_outbox() {
    let ctx = setup_sqlite_storage("private-expired-cleanup-batch").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [3; 16];
    let expired_delivery_id = "expired-private-cleanup-delivery";
    let dangling_delivery_id = "dangling-private-cleanup-delivery";

    ctx.storage
        .insert_private_message(
            expired_delivery_id,
            &PrivateMessage {
                payload: vec![1, 2, 3].into(),
                size: 3,
                sent_at: now - 10_000,
                expires_at: now - 1_000,
            },
        )
        .await
        .expect("expired payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: expired_delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now - 10_000,
                created_at: now - 10_000,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now - 10_000,
            },
        )
        .await
        .expect("expired outbox should be inserted");

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO private_outbox \
         (device_id, delivery_id, status, attempts, occurred_at, created_at, next_attempt_at, updated_at) \
         VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
    )
    .bind(&device_id[..])
    .bind(dangling_delivery_id)
    .bind(OUTBOX_STATUS_PENDING)
    .bind(now - 9_000)
    .bind(now - 9_000)
    .bind(now)
    .bind(now - 9_000)
    .execute(&mut conn)
    .await
    .expect("dangling outbox should be inserted");
    drop(conn);

    let removed = ctx
        .storage
        .cleanup_private_expired_data(now, 16)
        .await
        .expect("private cleanup should succeed");
    assert_eq!(removed, 2);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let remaining_payloads: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(expired_delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("payload count should be queryable");
    let remaining_outbox: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox WHERE delivery_id IN (?, ?)")
            .bind(expired_delivery_id)
            .bind(dangling_delivery_id)
            .fetch_one(&mut conn)
            .await
            .expect("outbox count should be queryable");
    assert_eq!(remaining_payloads, 0);
    assert_eq!(remaining_outbox, 0);
}

#[tokio::test]
async fn orphan_channel_cleanup_ignores_historical_stats_rows() {
    let ctx = setup_sqlite_storage("orphan-channel-cleanup-ignores-stats").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 10 * 60 * 1000;
    let stats_channel_id = [8u8; 16];
    let removable_channel_id = [9u8; 16];

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    for (channel_id, alias) in [
        (stats_channel_id, "orphan-with-historical-stats"),
        (removable_channel_id, "orphan-removable-without-stats"),
    ] {
        sqlx::query(
            "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
             VALUES (?, 'test-password-hash', ?, ?, ?)",
        )
        .bind(&channel_id[..])
        .bind(alias)
        .bind(old)
        .bind(old)
        .execute(&mut conn)
        .await
        .expect("test channel should be inserted");
    }
    sqlx::query("CREATE TABLE IF NOT EXISTS channel_stats_daily (channel_id BLOB NOT NULL, bucket_date TEXT NOT NULL, messages_routed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (channel_id, bucket_date))")
        .execute(&mut conn)
        .await
        .expect("legacy stats table should be created");
    sqlx::query("INSERT INTO channel_stats_daily (channel_id, bucket_date, messages_routed) VALUES (?, '2026-05-25', 1)")
        .bind(&stats_channel_id[..])
        .execute(&mut conn)
        .await
        .expect("legacy stats row should be inserted");
    drop(conn);

    let cleanup = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_channel_ttl_secs: 60,
                orphan_channel_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(cleanup.orphan_channels_pruned, 2);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let stats_channel_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE channel_id = ?")
            .bind(&stats_channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("stats channel count should be queryable");
    let removable_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE channel_id = ?")
            .bind(&removable_channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("removable channel count should be queryable");
    assert_eq!(stats_channel_exists, 0);
    assert_eq!(removable_exists, 0);
}

#[tokio::test]
async fn maintenance_cleanup_dry_run_does_not_remove_orphan_channels() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-dry-run-orphan-channel").await;
    let now = 1_700_000_000_000_i64;
    let removable_channel_id = [0x73; 16];
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO channels (channel_id, password_hash, alias, created_at, updated_at) \
         VALUES (?, 'hash', 'dry-run-orphan-channel', ?, ?)",
    )
    .bind(&removable_channel_id[..])
    .bind(now - 600_000)
    .bind(now - 600_000)
    .execute(&mut conn)
    .await
    .expect("orphan channel should be inserted");
    drop(conn);

    let dry_run = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_channel_ttl_secs: 60,
                orphan_channel_cleanup_enabled: true,
                dry_run: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("dry-run cleanup should succeed");
    assert_eq!(dry_run.orphan_channels_pruned, 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let still_exists: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM channels WHERE channel_id = ?")
            .bind(&removable_channel_id[..])
            .fetch_one(&mut conn)
            .await
            .expect("orphan channel should be queryable after dry-run");
    assert_eq!(still_exists, 1);
    drop(conn);

    let cleanup = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_channel_ttl_secs: 60,
                orphan_channel_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("real cleanup should succeed");
    assert_eq!(cleanup.orphan_channels_pruned, 1);
}

#[tokio::test]
async fn private_outbox_batch_rejects_device_overflow_without_eviction() {
    let ctx = setup_sqlite_storage("private-outbox-batch-prunes-device").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [3; 16];
    let mut batch = Vec::new();

    for index in 0_i64..3 {
        let delivery_id = format!("delivery-batch-prune-{index}");
        let message = PrivateMessage {
            payload: vec![index as u8].into(),
            size: 1,
            sent_at: now + index,
            expires_at: now + 300_000,
        };
        ctx.storage
            .insert_private_message(&delivery_id, &message)
            .await
            .expect("insert private message should succeed");
        batch.push(PrivateOutboxBatchEntry {
            device_id,
            entry: PrivateOutboxEntry {
                delivery_id,
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now + index,
                created_at: now + index,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now + index,
            },
        });
    }

    let err = ctx
        .storage
        .enqueue_private_outbox_batch(&batch, 2, 100, None)
        .await
        .expect_err("over-capacity batch must be rejected");
    assert!(matches!(
        err,
        StoreError::PrivateOutboxCapacityExceeded { .. }
    ));
    assert_eq!(
        ctx.storage
            .count_private_outbox_for_device(device_id)
            .await
            .expect("count should succeed"),
        0
    );
    assert!(
        ctx.storage
            .load_private_message("delivery-batch-prune-0")
            .await
            .expect("payload lookup should succeed")
            .is_some()
    );
    assert!(
        ctx.storage
            .load_private_message("delivery-batch-prune-2")
            .await
            .expect("payload lookup should succeed")
            .is_some()
    );
}

#[tokio::test]
async fn private_outbox_batch_preserves_existing_work_when_capacity_is_full() {
    let ctx = setup_sqlite_storage("private-outbox-batch-protects-current").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [4; 16];

    for index in 0_i64..2 {
        let delivery_id = format!("delivery-batch-protected-old-{index}");
        let message = PrivateMessage {
            payload: vec![index as u8].into(),
            size: 1,
            sent_at: now + index,
            expires_at: now + 300_000,
        };
        ctx.storage
            .insert_private_message(&delivery_id, &message)
            .await
            .expect("insert old private message should succeed");
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id,
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now + index,
                    created_at: now + index,
                    claimed_at: None,
                    claimed_by: None,
                    claim_generation: 0,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now + index,
                },
            )
            .await
            .expect("enqueue old outbox should succeed");
    }

    let current_delivery_id = "delivery-batch-protected-current";
    let current_message = PrivateMessage {
        payload: vec![9].into(),
        size: 1,
        sent_at: now + 3,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(current_delivery_id, &current_message)
        .await
        .expect("insert current private message should succeed");
    let err = ctx
        .storage
        .enqueue_private_outbox_batch(
            &[PrivateOutboxBatchEntry {
                device_id,
                entry: PrivateOutboxEntry {
                    delivery_id: current_delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now + 3,
                    created_at: now + 3,
                    claimed_at: None,
                    claimed_by: None,
                    claim_generation: 0,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now + 3,
                },
            }],
            2,
            100,
            Some(current_delivery_id),
        )
        .await
        .expect_err("full outbox must reject new work");
    assert!(matches!(
        err,
        StoreError::PrivateOutboxCapacityExceeded { .. }
    ));
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_id, current_delivery_id)
            .await
            .expect("current outbox lookup should succeed")
            .is_none()
    );
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_id, "delivery-batch-protected-old-0")
            .await
            .expect("old outbox lookup should succeed")
            .is_some()
    );
}

#[tokio::test]
async fn maintenance_cleanup_prunes_expired_runtime_rows_and_orphan_devices() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-defaults").await;
    let now = chrono::Utc::now().timestamp_millis();
    let stale_before = now - 120_000;
    let device_id: DeviceId = [11; 16];
    let old_route = DeviceRouteRecordRow {
        device_key: "maintenance-cleanup-orphan-device-key".to_string(),
        platform: "android".to_string(),
        channel_type: "private".to_string(),
        provider_token: None,
        updated_at: stale_before,
    };
    ctx.storage
        .upsert_device_route(&old_route)
        .await
        .expect("old orphan route should be persisted");

    let private_delivery_id = "maintenance-stale-private-outbox";
    let private_message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(private_delivery_id, &private_message)
        .await
        .expect("private payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: private_delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: stale_before,
                created_at: stale_before,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: stale_before,
                last_error_code: None,
                last_error_detail: None,
                updated_at: stale_before,
            },
        )
        .await
        .expect("stale private outbox should be inserted");

    let provider_delivery_id = "maintenance-expired-provider-pull";
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            provider_delivery_id,
            &PrivateMessage {
                payload: vec![4, 5, 6].into(),
                size: 3,
                sent_at: stale_before,
                expires_at: stale_before,
            },
            Platform::ANDROID,
            "maintenance-expired-provider-token",
        )
        .await
        .expect("expired provider pull row should be inserted");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                private_stale_outbox_ttl_secs: 60,
                orphan_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");

    assert_eq!(stats.private_outbox_pruned, 1);
    assert_eq!(stats.provider_pull_pruned, 1);
    assert_eq!(stats.orphan_devices_pruned, 1);

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM private_outbox")
        .fetch_one(&mut conn)
        .await
        .expect("outbox count should be queryable");
    let provider_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM provider_pull_queue")
        .fetch_one(&mut conn)
        .await
        .expect("provider pull count should be queryable");
    drop(conn);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let route_count: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_key = ?")
        .bind(&old_route.device_key)
        .fetch_one(&mut conn)
        .await
        .expect("device count should be queryable");
    assert_eq!(outbox_count, 0);
    assert_eq!(provider_count, 0);
    assert_eq!(route_count, 0);
}

#[tokio::test]
async fn maintenance_cleanup_keeps_recent_pending_op_dedupe_for_full_stale_window() {
    let ctx = setup_sqlite_storage("maintenance-op-dedupe-stale-window").await;
    let now = 1_700_000_000_000_i64;
    let recent_key = "maintenance-op-dedupe-recent";
    let stale_key = "maintenance-op-dedupe-stale";

    ctx.storage
        .reserve_op_dedupe_pending(recent_key, "delivery-recent-pending", now - 119_000)
        .await
        .expect("recent pending op dedupe should be reserved");
    ctx.storage
        .reserve_op_dedupe_pending(stale_key, "delivery-stale-pending", now - 121_000)
        .await
        .expect("stale pending op dedupe should be reserved");

    ctx.storage
        .run_maintenance_cleanup(now, MaintenanceCleanupConfig::default())
        .await
        .expect("maintenance cleanup should succeed");

    let mut conn = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("sqlite dispatch sidecar connection should succeed");
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT dedupe_key, state FROM dispatch_op_dedupe ORDER BY dedupe_key ASC")
            .fetch_all(&mut conn)
            .await
            .expect("op dedupe rows should be queryable");

    assert_eq!(
        rows,
        vec![(
            recent_key.to_string(),
            DedupeState::Pending.as_str().to_string()
        )]
    );
}

#[tokio::test]
async fn durable_submission_is_atomic_with_dedupe_and_survives_stale_cleanup() {
    let ctx = setup_sqlite_storage("durable-submission-atomic").await;
    let now = 1_700_000_000_000_i64;
    let submission = DispatchSubmissionRecord {
        dedupe_key: "op:submission:message:-:atomic-op".to_string(),
        delivery_id: "submission-atomic-delivery".to_string(),
        op_id: "atomic-op".to_string(),
        payload_version: 1,
        payload_blob: br#"{"frozen_targets":["device-a"]}"#.to_vec(),
        acceptance_order: 0,
        accepted_at: now - 300_000,
        expires_at: now + 60_000,
    };

    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("fingerprint-a"), &submission)
            .await
            .expect("submission reservation should succeed"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    let persisted = ctx
        .storage
        .list_pending_dispatch_submissions(10, now)
        .await
        .expect("pending submission should be readable");
    assert_eq!(persisted.len(), 1);
    assert!(persisted[0].acceptance_order > 0);
    let persisted_submission = persisted[0].clone();

    ctx.storage
        .cleanup_pending_op_dedupe(now, 10)
        .await
        .expect("stale cleanup should succeed");
    assert_eq!(
        ctx.storage
            .list_pending_dispatch_submissions(10, now)
            .await
            .expect("accepted submission must survive generic pending cleanup"),
        vec![persisted_submission]
    );

    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("fingerprint-a"), &DispatchSubmissionRecord {
                delivery_id: "must-not-replace-existing-delivery".to_string(),
                ..submission.clone()
            })
            .await
            .expect("duplicate submission lookup should succeed"),
        OpDedupeReservation::Pending { delivery_id }
            if delivery_id == submission.delivery_id
    ));
    assert!(
        ctx.storage
            .mark_op_dedupe_finalized(
                submission.dedupe_key.as_str(),
                submission.delivery_id.as_str(),
                DedupeState::Sent,
            )
            .await
            .expect("submission should finalize")
    );
    assert!(
        ctx.storage
            .list_pending_dispatch_submissions(10, now)
            .await
            .expect("finalized submission must leave recovery queue")
            .is_empty()
    );
    let mut dispatch = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("dispatch sidecar should open");
    let retained_manifests: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM dispatch_submission WHERE dedupe_key=?")
            .bind(&submission.dedupe_key)
            .fetch_one(&mut dispatch)
            .await
            .expect("terminal manifest count should be queryable");
    assert_eq!(
        retained_manifests, 0,
        "finalization must compact the large frozen manifest immediately"
    );
}

#[tokio::test]
async fn dispatch_acceptance_order_is_total_across_same_millis_restart_and_clock_rollback() {
    let ctx = setup_sqlite_storage("dispatch-acceptance-total-order").await;
    let make_submission = |suffix: &str, accepted_at: i64| DispatchSubmissionRecord {
        dedupe_key: format!("op:submission:event:{suffix}:order-{suffix}"),
        delivery_id: format!("delivery-order-{suffix}"),
        op_id: format!("order-{suffix}"),
        payload_version: 1,
        payload_blob: br#"{"event":"snapshot"}"#.to_vec(),
        acceptance_order: 0,
        accepted_at,
        expires_at: accepted_at + 60_000,
    };
    let same_millis = 1_800_000_000_000;
    let first = make_submission("first", same_millis);
    let second = make_submission("second", same_millis);
    let (first_result, second_result) = tokio::join!(
        ctx.storage.reserve_dispatch_submission(None, &first),
        ctx.storage.reserve_dispatch_submission(None, &second),
    );
    assert!(matches!(
        first_result.unwrap(),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(matches!(
        second_result.unwrap(),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    let first_order = ctx
        .storage
        .load_dispatch_submission_acceptance_order(&first.dedupe_key, &first.delivery_id)
        .await
        .unwrap()
        .unwrap();
    let second_order = ctx
        .storage
        .load_dispatch_submission_acceptance_order(&second.dedupe_key, &second.delivery_id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        first_order, second_order,
        "same-millisecond accepts need a total order"
    );

    let previous_max = first_order.max(second_order);
    let db_url = ctx.db_url.clone();
    drop(ctx.storage);
    let reopened = Storage::new(Some(&db_url))
        .await
        .expect("single instance should reopen the same v12 database");
    let after_rollback = make_submission("after-restart", same_millis - 10_000);
    assert!(matches!(
        reopened
            .reserve_dispatch_submission(None, &after_rollback)
            .await
            .unwrap(),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    let reopened_order = reopened
        .load_dispatch_submission_acceptance_order(
            &after_rollback.dedupe_key,
            &after_rollback.delivery_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        reopened_order > previous_max,
        "database order must survive restart and ignore wall-clock rollback"
    );
}

#[tokio::test]
async fn unrecoverable_submission_terminalization_is_atomic_and_reclaims_capacity() {
    let ctx = setup_sqlite_storage("durable-submission-unrecoverable").await;
    let now = 1_700_000_000_000_i64;
    let submission = DispatchSubmissionRecord {
        dedupe_key: "op:submission:message:-:unrecoverable-op".to_string(),
        delivery_id: "submission-unrecoverable-delivery".to_string(),
        op_id: "unrecoverable-op".to_string(),
        payload_version: 999,
        payload_blob: b"not-a-supported-manifest".to_vec(),
        acceptance_order: 0,
        accepted_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: submission.op_id.clone(),
            channel_id: [73; 16],
            model: "message".to_string(),
            entity_id: "unrecoverable-entity".to_string(),
            status: SenderSubmitStatusKind::Processing,
            dispatch_status: None,
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("sender status should be inserted");
    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("unrecoverable-fingerprint"), &submission)
            .await
            .expect("submission should reserve"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));

    assert!(
        ctx.storage
            .terminalize_unrecoverable_dispatch_submission(
                &submission,
                "unrecoverable_unknown_payload_version",
                now + 1,
            )
            .await
            .expect("terminal transition should succeed")
    );
    assert!(
        ctx.storage
            .list_pending_dispatch_submissions(10, now + 2)
            .await
            .expect("recovery queue should be readable")
            .is_empty()
    );
    let status = ctx
        .storage
        .load_sender_submit_status(&submission.op_id)
        .await
        .expect("sender status should be readable")
        .expect("sender status should remain");
    assert_eq!(status.status, SenderSubmitStatusKind::Failed);
    assert_eq!(
        status.dispatch_status.as_deref(),
        Some("unrecoverable_unknown_payload_version")
    );
    assert!(
        !ctx.storage
            .terminalize_unrecoverable_dispatch_submission(
                &submission,
                "unrecoverable_unknown_payload_version",
                now + 3,
            )
            .await
            .expect("duplicate terminal transition should be idempotent")
    );
}

#[tokio::test]
async fn dispatch_submission_capacity_rejects_atomically_before_acceptance() {
    let ctx = setup_sqlite_storage("dispatch-submission-capacity").await;
    let make_submission = |suffix: &str, accepted_at: i64| DispatchSubmissionRecord {
        dedupe_key: format!("op:submission:message:-:capacity-{suffix}"),
        delivery_id: format!("submission-capacity-delivery-{suffix}"),
        op_id: format!("capacity-{suffix}"),
        payload_version: 1,
        payload_blob: br#"{"frozen_targets":["device-a"]}"#.to_vec(),
        acceptance_order: 0,
        accepted_at,
        expires_at: accepted_at + 60_000,
    };
    let first = make_submission("first", 1_700_000_000_000);
    let second = make_submission("second", 1_700_000_000_001);

    assert!(matches!(
        ctx.storage
            .db
            .reserve_op_dedupe_pending(
                &first.dedupe_key,
                &first.delivery_id,
                Some("fingerprint-first"),
                first.accepted_at,
                Some(&first),
                1,
            )
            .await
            .expect("first capacity slot should reserve"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(matches!(
        ctx.storage
            .db
            .reserve_op_dedupe_pending(
                &second.dedupe_key,
                &second.delivery_id,
                Some("fingerprint-second"),
                second.accepted_at,
                Some(&second),
                1,
            )
            .await,
        Err(StoreError::DispatchSubmissionCapacityExceeded {
            pending: 1,
            capacity: 1
        })
    ));

    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("fingerprint-second"), &second)
            .await
            .expect("capacity rejection must roll back its dedupe identity"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
}

#[tokio::test]
async fn durable_submission_materialization_lease_is_exclusive_renewable_and_fenced() {
    let ctx = setup_sqlite_storage("durable-submission-materialization-lease").await;
    let now = 1_700_000_000_000_i64;
    let submission = DispatchSubmissionRecord {
        dedupe_key: "op:submission:message:-:lease-op".to_string(),
        delivery_id: "submission-lease-delivery".to_string(),
        op_id: "lease-op".to_string(),
        payload_version: 1,
        payload_blob: br#"{"frozen_targets":["device-a"]}"#.to_vec(),
        acceptance_order: 0,
        accepted_at: now,
        expires_at: now + 60_000,
    };
    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("fingerprint-lease"), &submission)
            .await
            .expect("submission reservation should succeed"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));

    assert!(
        ctx.storage
            .claim_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-a",
                now,
                now + 15_000,
            )
            .await
            .expect("first materializer claim")
    );
    assert!(
        !ctx.storage
            .claim_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-b",
                now + 1,
                now + 15_001,
            )
            .await
            .expect("concurrent materializer claim")
    );
    assert!(
        ctx.storage
            .list_pending_dispatch_submissions(10, now + 1)
            .await
            .expect("leased submissions should be filtered from the due recovery scan")
            .is_empty()
    );
    assert!(
        !ctx.storage
            .renew_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-b",
                now + 2,
                now + 15_002,
            )
            .await
            .expect("stale materializer renewal")
    );
    assert!(
        ctx.storage
            .renew_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-a",
                now + 2,
                now + 15_002,
            )
            .await
            .expect("owner materializer renewal")
    );
    assert!(
        !ctx.storage
            .release_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-b",
                now + 3,
            )
            .await
            .expect("stale materializer release")
    );
    assert!(
        ctx.storage
            .release_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-a",
                now + 3,
            )
            .await
            .expect("owner materializer release")
    );
    let mut persisted_submission = submission.clone();
    persisted_submission.acceptance_order = ctx
        .storage
        .load_dispatch_submission_acceptance_order(&submission.dedupe_key, &submission.delivery_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ctx.storage
            .list_pending_dispatch_submissions(10, now + 4)
            .await
            .expect("released submission should return to the due recovery scan"),
        vec![persisted_submission]
    );
    assert!(
        ctx.storage
            .claim_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "materializer-b",
                now + 4,
                now + 15_004,
            )
            .await
            .expect("released submission should be immediately reclaimable")
    );
}

#[tokio::test]
async fn private_capacity_accelerator_survives_transient_lease_release_failure() {
    let ctx = setup_sqlite_storage("private-capacity-release-retry").await;
    let now = 1_700_000_000_000_i64;
    let device_id: DeviceId = [74; 16];
    let submission = DispatchSubmissionRecord {
        dedupe_key: "op:submission:message:-:capacity-retry-op".to_string(),
        delivery_id: "submission-capacity-retry-delivery".to_string(),
        op_id: "capacity-retry-op".to_string(),
        payload_version: 1,
        payload_blob: br#"{"frozen_targets":["device-a"]}"#.to_vec(),
        acceptance_order: 0,
        accepted_at: now,
        expires_at: now + 60_000,
    };
    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("capacity-retry-fingerprint"), &submission)
            .await
            .expect("submission should reserve"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(
        ctx.storage
            .claim_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "capacity-retry-owner",
                now,
                now + 20_000,
            )
            .await
            .expect("submission lease should claim")
    );
    ctx.storage.register_private_capacity_blocked_submission(
        &submission.dedupe_key,
        &submission.delivery_id,
        "capacity-retry-owner",
        &[device_id],
    );

    ctx.storage.inject_submission_release_failures(1);
    assert!(
        ctx.storage
            .note_private_capacity_released(Some(device_id), 1)
            .await
            .is_err(),
        "the injected database failure must surface"
    );
    assert_eq!(
        ctx.storage
            .expedite_private_capacity_recovery(Some(device_id), 1)
            .await
            .expect("retained accelerator entry should retry"),
        1,
        "a transient failure must not consume the accelerator registration"
    );
    assert!(
        ctx.storage
            .claim_dispatch_submission_materialization(
                &submission.dedupe_key,
                &submission.delivery_id,
                "capacity-retry-next-owner",
                now + 1,
                now + 20_001,
            )
            .await
            .expect("released durable lease should be immediately claimable")
    );
}

#[tokio::test]
async fn provider_terminal_settlement_cannot_finalize_a_partially_materialized_submission() {
    let ctx = setup_sqlite_storage("provider-terminal-does-not-finalize-pending-submission").await;
    let now = 1_700_000_000_000_i64;
    let op_id = "provider-terminal-pending-op";
    let delivery_id = "provider-terminal-pending-delivery";
    let submission = DispatchSubmissionRecord {
        dedupe_key: format!("op:submission:message:-:{op_id}"),
        delivery_id: delivery_id.to_string(),
        op_id: op_id.to_string(),
        payload_version: 1,
        payload_blob: br#"{"frozen_targets":["private-full","apns-healthy"]}"#.to_vec(),
        acceptance_order: 0,
        accepted_at: now,
        expires_at: now + 60_000,
    };
    assert!(matches!(
        ctx.storage
            .reserve_dispatch_submission(Some("pending-provider-terminal-fingerprint"), &submission)
            .await
            .expect("pending submission reservation should succeed"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [41; 16],
            model: "message".to_string(),
            entity_id: "pending-provider-terminal-entity".to_string(),
            status: SenderSubmitStatusKind::Processing,
            dispatch_status: Some("materialization_pending".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("sender status should be inserted");

    ctx.storage
        .finalize_provider_dispatch_outcome(
            submission.dedupe_key.as_str(),
            op_id,
            delivery_id,
            true,
        )
        .await
        .expect("early provider terminal observation should be a fenced no-op");

    let mut dispatch = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("dispatch verification connection should succeed");
    let dedupe_state: String =
        sqlx::query_scalar("SELECT state FROM dispatch_op_dedupe WHERE dedupe_key = ?")
            .bind(submission.dedupe_key.as_str())
            .fetch_one(&mut dispatch)
            .await
            .expect("dedupe state should remain readable");
    let manifest_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM dispatch_submission WHERE dedupe_key = ?")
            .bind(submission.dedupe_key.as_str())
            .fetch_one(&mut dispatch)
            .await
            .expect("manifest should remain readable");
    assert_eq!(dedupe_state, DedupeState::Pending.as_str());
    assert_eq!(manifest_count, 1);

    let sender = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("sender status lookup should succeed")
        .expect("sender status should remain present");
    assert_eq!(sender.status, SenderSubmitStatusKind::Processing);
}

#[tokio::test]
async fn maintenance_cleanup_prunes_expired_sender_submit_status() {
    let ctx = setup_sqlite_storage("maintenance-sender-status").await;
    let now = 1_700_000_000_000_i64;
    let expired = SenderSubmitStatusRecord {
        op_id: "0018bcfe56800-expiredsenderstatus000000000001".to_string(),
        channel_id: [1; 16],
        model: "message".to_string(),
        entity_id: "message-expired".to_string(),
        status: SenderSubmitStatusKind::Sent,
        dispatch_status: Some("attempted_accepted".to_string()),
        accepted_at: now - 90_000,
        updated_at: now - 80_000,
        expires_at: now - 1,
    };
    let live = SenderSubmitStatusRecord {
        op_id: "0018bcfe56800-livesenderstatus00000000000001".to_string(),
        channel_id: [2; 16],
        model: "message".to_string(),
        entity_id: "message-live".to_string(),
        status: SenderSubmitStatusKind::Processing,
        dispatch_status: None,
        accepted_at: now,
        updated_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .insert_sender_submit_status_if_absent(&expired)
        .await
        .expect("expired sender status should insert");
    ctx.storage
        .insert_sender_submit_status_if_absent(&live)
        .await
        .expect("live sender status should insert");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(now, MaintenanceCleanupConfig::default())
        .await
        .expect("maintenance cleanup should succeed");

    assert_eq!(stats.sender_status_pruned, 1);
    assert!(
        ctx.storage
            .load_sender_submit_status(&expired.op_id)
            .await
            .expect("expired sender status lookup should succeed")
            .is_none()
    );
    assert_eq!(
        ctx.storage
            .load_sender_submit_status(&live.op_id)
            .await
            .expect("live sender status lookup should succeed")
            .expect("live sender status should remain")
            .status,
        SenderSubmitStatusKind::Processing
    );
}

#[tokio::test]
async fn interrupted_provider_dispatch_recovery_fails_closed_after_lease_expiry() {
    let ctx = setup_sqlite_storage("provider-dispatch-interrupted-recovery").await;
    let now = chrono::Utc::now().timestamp_millis();
    let op_id = "provider-interrupted-retry-op";
    let delivery_id = "provider-interrupted-retry-delivery";
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(op_id, delivery_id, now)
            .await
            .expect("reserve interrupted op"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(
        ctx.storage
            .mark_op_dedupe_finalized(op_id, delivery_id, DedupeState::ProviderQueued)
            .await
            .expect("mark interrupted op provider queued")
    );
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [8; 16],
            model: "message".to_string(),
            entity_id: "provider-interrupted-entity".to_string(),
            status: SenderSubmitStatusKind::ProviderQueued,
            dispatch_status: Some("provider_queued".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("insert interrupted sender status");

    let active_recovered = ctx
        .storage
        .recover_interrupted_provider_dispatches(now + 1)
        .await
        .expect("active provider lease recovery should succeed");
    assert_eq!(
        active_recovered, 0,
        "an active provider lease must be preserved"
    );
    let active_status = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("load active sender status")
        .expect("active sender status should exist");
    assert_eq!(active_status.status, SenderSubmitStatusKind::ProviderQueued);

    let mut dispatch_conn = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("dispatch sidecar connection should succeed");
    let provider_run: (Option<String>, Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT provider_run_token, provider_owner, provider_lease_until \
         FROM dispatch_op_dedupe WHERE dedupe_key = ?",
    )
    .bind(op_id)
    .fetch_one(&mut dispatch_conn)
    .await
    .expect("provider run metadata should be queryable");
    assert!(
        provider_run
            .0
            .as_deref()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        provider_run
            .1
            .as_deref()
            .is_some_and(|owner| !owner.is_empty())
    );
    assert!(provider_run.2.is_some_and(|lease_until| lease_until > now));
    sqlx::query("UPDATE dispatch_op_dedupe SET provider_lease_until = ? WHERE dedupe_key = ?")
        .bind(now)
        .bind(op_id)
        .execute(&mut dispatch_conn)
        .await
        .expect("provider lease should be expired for recovery test");

    let recovered = ctx
        .storage
        .recover_interrupted_provider_dispatches(now + 2)
        .await
        .expect("expired provider lease recovery should succeed");
    assert_eq!(recovered, 1);
    let status = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("load recovered sender status")
        .expect("recovered sender status should exist");
    assert_eq!(status.status, SenderSubmitStatusKind::Failed);
    assert_eq!(
        status.dispatch_status.as_deref(),
        Some("provider_outcome_unknown")
    );
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(op_id, "provider-interrupted-retry-delivery-2", now + 2)
            .await
            .expect("retry lookup should succeed after recovery"),
        OpDedupeReservation::PartialFailure { .. }
    ));
}

#[tokio::test]
async fn interrupted_provider_dispatch_recovery_preserves_durable_pending_work() {
    let ctx = setup_sqlite_storage("provider-dispatch-durable-recovery").await;
    let now = chrono::Utc::now().timestamp_millis();
    let op_id = "provider-durable-recovery-op";
    let dedupe_key = format!("op:channel:message:entity:{op_id}");
    let delivery_id = "provider-durable-recovery-delivery";
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now)
            .await
            .expect("reserve durable interrupted op"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(
        ctx.storage
            .mark_op_dedupe_finalized(&dedupe_key, delivery_id, DedupeState::ProviderQueued,)
            .await
            .expect("mark durable interrupted op provider queued")
    );
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [18; 16],
            model: "message".to_string(),
            entity_id: "provider-durable-recovery-entity".to_string(),
            status: SenderSubmitStatusKind::ProviderQueued,
            dispatch_status: Some("provider_queued".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("insert durable interrupted sender status");
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&ProviderDispatchOutboxRecord {
                job_id: "provider-durable-recovery-job".to_string(),
                provider: "FCM".to_string(),
                delivery_id: delivery_id.to_string(),
                op_id: Some(op_id.to_string()),
                dedupe_key: Some(dedupe_key.clone()),
                device_key: "provider-durable-recovery-device".to_string(),
                payload_blob: b"durable-provider-payload".to_vec(),
                state: "pending".to_string(),
                next_attempt_at: now,
                accepted_at: now,
                expires_at: now + 60_000,
                coalesce_order: 0,
                coalescible: false,
            })
            .await
            .expect("persist interrupted provider work")
    );

    let mut dispatch_conn = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("dispatch sidecar connection should succeed");
    sqlx::query("UPDATE dispatch_op_dedupe SET provider_lease_until = ? WHERE dedupe_key = ?")
        .bind(now)
        .bind(&dedupe_key)
        .execute(&mut dispatch_conn)
        .await
        .expect("provider operation lease should expire");

    assert_eq!(
        ctx.storage
            .recover_interrupted_provider_dispatches(now + 1)
            .await
            .expect("durable interrupted provider recovery should succeed"),
        1
    );
    let dedupe_state: String =
        sqlx::query_scalar("SELECT state FROM dispatch_op_dedupe WHERE dedupe_key = ?")
            .bind(&dedupe_key)
            .fetch_one(&mut dispatch_conn)
            .await
            .expect("durable dedupe state should remain queryable");
    assert_eq!(dedupe_state, DedupeState::ProviderQueued.as_str());
    let sender = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("load durable recovery sender status")
        .expect("durable recovery sender status should exist");
    assert_eq!(sender.status, SenderSubmitStatusKind::ProviderQueued);
    assert!(
        ctx.storage
            .claim_provider_dispatch_job(
                "FCM",
                None,
                "provider-durable-recovery-owner",
                now + 1,
                now + 30_001,
            )
            .await
            .expect("recovered provider work should remain claimable")
            .is_some()
    );
}

#[tokio::test]
async fn interrupted_provider_dispatch_recovery_finalizes_terminal_durable_work() {
    let ctx = setup_sqlite_storage("provider-dispatch-terminal-recovery").await;
    let now = chrono::Utc::now().timestamp_millis();
    let op_id = "provider-terminal-recovery-op";
    let dedupe_key = format!("op:channel:message:entity:{op_id}");
    let delivery_id = "provider-terminal-recovery-delivery";
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now)
            .await
            .expect("reserve terminal recovery op"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(
        ctx.storage
            .mark_op_dedupe_finalized(&dedupe_key, delivery_id, DedupeState::ProviderQueued,)
            .await
            .expect("mark terminal recovery op provider queued")
    );
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [19; 16],
            model: "message".to_string(),
            entity_id: "provider-terminal-recovery-entity".to_string(),
            status: SenderSubmitStatusKind::ProviderQueued,
            dispatch_status: Some("provider_queued".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("insert terminal recovery sender status");
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&ProviderDispatchOutboxRecord {
                job_id: "provider-terminal-recovery-job".to_string(),
                provider: "FCM".to_string(),
                delivery_id: delivery_id.to_string(),
                op_id: Some(op_id.to_string()),
                dedupe_key: Some(dedupe_key.clone()),
                device_key: "provider-terminal-recovery-device".to_string(),
                payload_blob: b"terminal-provider-payload".to_vec(),
                state: "pending".to_string(),
                next_attempt_at: now,
                accepted_at: now,
                expires_at: now + 60_000,
                coalesce_order: 0,
                coalescible: false,
            })
            .await
            .expect("persist terminal provider work")
    );
    let lease = ctx
        .storage
        .claim_provider_dispatch_job(
            "FCM",
            None,
            "provider-terminal-recovery-owner",
            now,
            now + 30_000,
        )
        .await
        .expect("terminal provider work claim should succeed")
        .expect("terminal provider work should be claimable");
    assert!(
        ctx.storage
            .settle_provider_dispatch_job(
                &lease,
                ProviderDispatchSettlement::Accepted,
                now + 1,
                200,
                None,
                now + 1,
            )
            .await
            .expect("terminal provider work should settle")
    );

    assert_eq!(
        ctx.storage
            .recover_interrupted_provider_dispatches(now + 2)
            .await
            .expect("terminal provider recovery should succeed"),
        1
    );
    let sender = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("load terminal recovery sender status")
        .expect("terminal recovery sender status should exist");
    assert_eq!(sender.status, SenderSubmitStatusKind::Sent);
    assert_eq!(sender.dispatch_status.as_deref(), Some("provider_success"));
    let recovered_reservation = ctx
        .storage
        .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now + 3)
        .await
        .expect("terminal recovery dedupe lookup should succeed");
    assert!(
        matches!(recovered_reservation, OpDedupeReservation::Sent { .. }),
        "terminal recovery dedupe must be sent, got {recovered_reservation:?}"
    );
}

#[tokio::test]
async fn provider_ttl_expiry_finalizes_without_waiting_for_operation_lease() {
    let ctx = setup_sqlite_storage("provider-dispatch-expiry-finalization").await;
    let now = chrono::Utc::now().timestamp_millis();
    let op_id = "provider-expiry-finalization-op";
    let dedupe_key = format!("op:channel:message:entity:{op_id}");
    let delivery_id = "provider-expiry-finalization-delivery";
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now)
            .await
            .expect("reserve expiring provider op"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(
        ctx.storage
            .mark_op_dedupe_finalized(&dedupe_key, delivery_id, DedupeState::ProviderQueued)
            .await
            .expect("mark expiring provider op queued")
    );
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [20; 16],
            model: "message".to_string(),
            entity_id: "provider-expiry-finalization-entity".to_string(),
            status: SenderSubmitStatusKind::ProviderQueued,
            dispatch_status: Some("provider_queued".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("insert expiring provider sender status");
    assert!(
        ctx.storage
            .enqueue_provider_dispatch_job(&ProviderDispatchOutboxRecord {
                job_id: "provider-expiry-finalization-job".to_string(),
                provider: "FCM".to_string(),
                delivery_id: delivery_id.to_string(),
                op_id: Some(op_id.to_string()),
                dedupe_key: Some(dedupe_key.clone()),
                device_key: "provider-expiry-finalization-device".to_string(),
                payload_blob: b"expiring-provider-payload".to_vec(),
                state: "pending".to_string(),
                next_attempt_at: now + 20_000,
                accepted_at: now,
                expires_at: now + 10,
                coalesce_order: 0,
                coalescible: false,
            })
            .await
            .expect("persist expiring provider work")
    );

    assert_eq!(
        ctx.storage
            .recover_expired_provider_dispatch_leases(now + 11)
            .await
            .expect("provider expiry sweep should succeed"),
        1
    );
    assert_eq!(
        ctx.storage
            .recover_interrupted_provider_dispatches(now + 12)
            .await
            .expect("terminal provider reconciliation should succeed"),
        1,
        "terminal rows must bypass the still-live 15-minute operation lease"
    );
    let sender = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("load expired provider sender status")
        .expect("expired provider sender status should exist");
    assert_eq!(sender.status, SenderSubmitStatusKind::PartiallyFailed);
    assert_eq!(sender.dispatch_status.as_deref(), Some("provider_failed"));
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now + 13)
            .await
            .expect("expired provider dedupe lookup should succeed"),
        OpDedupeReservation::PartialFailure { .. }
    ));
}

#[tokio::test]
async fn sender_submit_status_rejects_stale_and_terminal_regressions() {
    let ctx = setup_sqlite_storage("sender-status-monotonic-cas").await;
    let op_id = "sender-status-monotonic-op";
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [9; 16],
            model: "message".to_string(),
            entity_id: "sender-status-monotonic-entity".to_string(),
            status: SenderSubmitStatusKind::Accepted,
            dispatch_status: None,
            accepted_at: 100,
            updated_at: 100,
            expires_at: 10_000,
        })
        .await
        .expect("sender status should be inserted");
    ctx.storage
        .update_sender_submit_status(op_id, SenderSubmitStatusKind::Processing, None, 200)
        .await
        .expect("processing transition should succeed");
    ctx.storage
        .update_sender_submit_status(
            op_id,
            SenderSubmitStatusKind::Sent,
            Some("attempted_accepted"),
            300,
        )
        .await
        .expect("sent transition should succeed");
    ctx.storage
        .update_sender_submit_status(op_id, SenderSubmitStatusKind::Failed, None, 250)
        .await
        .expect("stale failure should be ignored without error");
    ctx.storage
        .update_sender_submit_status(
            op_id,
            SenderSubmitStatusKind::ProviderQueued,
            Some("provider_queued"),
            400,
        )
        .await
        .expect("terminal regression should be ignored without error");

    let status = ctx
        .storage
        .load_sender_submit_status(op_id)
        .await
        .expect("sender status lookup should succeed")
        .expect("sender status should remain");
    assert_eq!(status.status, SenderSubmitStatusKind::Sent);
    assert_eq!(status.updated_at, 300);
    assert_eq!(
        status.dispatch_status.as_deref(),
        Some("attempted_accepted")
    );
}

#[tokio::test]
async fn maintenance_cleanup_keeps_orphan_candidates_with_live_private_references() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-live-references").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let session_device_key = "maintenance-live-session-device-key";
    let queue_device_key = "maintenance-live-queue-device-key";
    let session_device_id = derive_private_device_id(session_device_key);
    let queue_device_id = derive_private_device_id(queue_device_key);

    for device_key in [session_device_key, queue_device_key] {
        ctx.storage
            .upsert_device_route(&DeviceRouteRecordRow {
                device_key: device_key.to_string(),
                platform: "android".to_string(),
                channel_type: "private".to_string(),
                provider_token: None,
                updated_at: old,
            })
            .await
            .expect("old route should be persisted");
    }

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query(
        "INSERT INTO private_sessions (session_id, device_id, expires_at) VALUES (?, ?, ?)",
    )
    .bind("maintenance-live-session")
    .bind(&session_device_id[..])
    .bind(now + 300_000)
    .execute(&mut conn)
    .await
    .expect("live private session should be inserted");

    ctx.storage
        .enqueue_provider_pull_item(
            queue_device_id,
            "maintenance-live-provider-pull",
            &PrivateMessage {
                payload: vec![3, 2, 1].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "maintenance-live-provider-token",
        )
        .await
        .expect("live provider pull row should be inserted");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                orphan_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");

    assert_eq!(stats.orphan_devices_pruned, 0);
    let route_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_key IN (?, ?)")
            .bind(session_device_key)
            .bind(queue_device_key)
            .fetch_one(&mut conn)
            .await
            .expect("route count should be queryable");
    assert_eq!(route_count, 2);
}

#[tokio::test]
async fn maintenance_cleanup_does_not_delete_shared_delivery_for_other_devices() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-shared-delivery").await;
    let now = chrono::Utc::now().timestamp_millis();
    let stale = now - 120_000;
    let device_a: DeviceId = [21; 16];
    let device_b: DeviceId = [22; 16];
    let shared_private_delivery_id = "maintenance-shared-private-delivery";
    let private_message = PrivateMessage {
        payload: vec![7, 8, 9].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(shared_private_delivery_id, &private_message)
        .await
        .expect("shared private payload should be inserted");
    for (device_id, updated_at) in [(device_a, stale), (device_b, now)] {
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: shared_private_delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: updated_at,
                    created_at: updated_at,
                    claimed_at: None,
                    claimed_by: None,
                    claim_generation: 0,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: updated_at,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at,
                },
            )
            .await
            .expect("shared private outbox should be inserted");
    }

    let provider_delivery_id = "maintenance-shared-provider-delivery";
    ctx.storage
        .enqueue_provider_pull_item(
            device_a,
            provider_delivery_id,
            &PrivateMessage {
                payload: vec![1].into(),
                size: 1,
                sent_at: stale,
                expires_at: stale,
            },
            Platform::ANDROID,
            "maintenance-shared-provider-token-a",
        )
        .await
        .expect("expired provider pull row should be inserted");
    ctx.storage
        .enqueue_provider_pull_item(
            device_b,
            provider_delivery_id,
            &PrivateMessage {
                payload: vec![2].into(),
                size: 1,
                sent_at: now,
                expires_at: now + 300_000,
            },
            Platform::ANDROID,
            "maintenance-shared-provider-token-b",
        )
        .await
        .expect("live provider pull row should be inserted");

    let stats = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                private_stale_outbox_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(stats.private_outbox_pruned, 1);
    assert_eq!(stats.provider_pull_pruned, 1);

    assert!(
        ctx.storage
            .load_private_outbox_entry(device_a, shared_private_delivery_id)
            .await
            .expect("device a private outbox lookup should succeed")
            .is_none()
    );
    assert!(
        ctx.storage
            .load_private_outbox_entry(device_b, shared_private_delivery_id)
            .await
            .expect("device b private outbox lookup should succeed")
            .is_some()
    );
    assert!(
        ctx.storage
            .load_private_message(shared_private_delivery_id)
            .await
            .expect("shared private payload lookup should succeed")
            .is_some()
    );

    let mut conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("sqlite test connection should succeed");
    let live_provider_for_b: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(&device_b[..])
    .bind(provider_delivery_id)
    .fetch_one(&mut conn)
    .await
    .expect("provider pull count should be queryable");
    let expired_provider_for_a: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(&device_a[..])
    .bind(provider_delivery_id)
    .fetch_one(&mut conn)
    .await
    .expect("provider pull count should be queryable");
    assert_eq!(live_provider_for_b, 1);
    assert_eq!(expired_provider_for_a, 0);
}

#[tokio::test]
async fn maintenance_cleanup_keeps_active_subscriptions_until_switch_is_enabled() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-switches").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let device_key = "maintenance-active-subscription-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-active-subscription-0001",
        "maintenance-active-subscription",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("UPDATE devices SET route_updated_at = ? WHERE device_id = ?")
        .bind(old)
        .bind(&device_id[..])
        .execute(&mut conn)
        .await
        .expect("route timestamp should be aged");
    sqlx::query(
        "UPDATE channel_subscriptions SET updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription timestamp should be aged");

    let disabled = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(disabled.stale_subscriptions_pruned, 0);

    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, "active");

    let enabled = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_ttl_secs: 60,
                stale_subscription_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(enabled.stale_subscriptions_pruned, 1);
}

#[tokio::test]
async fn maintenance_cleanup_keeps_subscription_after_recent_device_activity() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-recent-device-activity").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 120_000;
    let device_key = "maintenance-recent-activity-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-recent-activity-0001",
        "maintenance-recent-activity",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("UPDATE devices SET route_updated_at = ? WHERE device_id = ?")
        .bind(old)
        .bind(&device_id[..])
        .execute(&mut conn)
        .await
        .expect("route timestamp should be aged");
    sqlx::query(
        "UPDATE channel_subscriptions SET updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription timestamp should be aged");
    drop(conn);

    ctx.storage
        .touch_device_activity(device_id, now)
        .await
        .expect("device activity touch should succeed");

    let cleanup = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_ttl_secs: 60,
                stale_subscription_cleanup_enabled: true,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should succeed");
    assert_eq!(cleanup.stale_subscriptions_pruned, 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, "active");
}

#[tokio::test]
async fn maintenance_cleanup_freezes_inactive_subscriptions_before_hard_delete() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-subscription-lifecycle").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 240_000;
    let device_key = "maintenance-subscription-lifecycle-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-subscription-lifecycle-0001",
        "maintenance-subscription-lifecycle",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("UPDATE devices SET route_updated_at = ? WHERE device_id = ?")
        .bind(old)
        .bind(&device_id[..])
        .execute(&mut conn)
        .await
        .expect("route timestamp should be aged");
    sqlx::query(
        "UPDATE channel_subscriptions SET status = 'inactive', updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription should be marked inactive");

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, now)
        .await
        .expect("dispatch targets should be queryable");
    assert!(
        targets.is_empty(),
        "inactive subscriptions must not receive dispatch targets"
    );

    let frozen = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: false,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should freeze inactive subscription");
    assert_eq!(frozen.stale_subscriptions_pruned, 0);
    assert_eq!(frozen.frozen_subscriptions_pruned, 1);
    assert_eq!(frozen.soft_deleted_devices_pruned, 0);

    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, crate::storage::SUBSCRIPTION_STATUS_FROZEN);

    let hard_deleted = ctx
        .storage
        .run_maintenance_cleanup(
            now + 120_000,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: true,
                soft_deleted_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should delete removable frozen route");
    assert_eq!(hard_deleted.soft_deleted_devices_pruned, 1);

    let device_exists: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE device_id = ?")
        .bind(&device_id[..])
        .fetch_one(&mut conn)
        .await
        .expect("device count should be queryable");
    assert_eq!(device_exists, 0);
}

#[tokio::test]
async fn maintenance_cleanup_blocks_freeze_and_delete_with_pending_private_outbox() {
    let ctx = setup_sqlite_storage("maintenance-cleanup-private-outbox-gate").await;
    let now = chrono::Utc::now().timestamp_millis();
    let old = now - 240_000;
    let device_key = "maintenance-private-outbox-gate-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        "android-token-maintenance-private-outbox-gate-0001",
        "maintenance-private-outbox-gate",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let device_id = derive_private_device_id(device_key);
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("UPDATE devices SET route_updated_at = ? WHERE device_id = ?")
        .bind(old)
        .bind(&device_id[..])
        .execute(&mut conn)
        .await
        .expect("route timestamp should be aged");
    sqlx::query(
        "UPDATE channel_subscriptions SET status = 'inactive', updated_at = ? WHERE channel_id = ? AND device_id = ?",
    )
    .bind(old)
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .execute(&mut conn)
    .await
    .expect("subscription should be marked inactive");
    drop(conn);

    let delivery_id = "maintenance-private-outbox-gate-delivery";
    ctx.storage
        .insert_private_message(
            delivery_id,
            &PrivateMessage {
                payload: vec![4, 5, 6].into(),
                size: 3,
                sent_at: now,
                expires_at: now + 300_000,
            },
        )
        .await
        .expect("pending private payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: old,
                created_at: old,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now + 300_000,
                last_error_code: None,
                last_error_detail: None,
                updated_at: old,
            },
        )
        .await
        .expect("pending private outbox should be inserted");

    let blocked = ctx
        .storage
        .run_maintenance_cleanup(
            now,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: true,
                soft_deleted_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should run with pending outbox");
    assert_eq!(blocked.frozen_subscriptions_pruned, 0);
    assert_eq!(blocked.soft_deleted_devices_pruned, 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let status: String = sqlx::query_scalar(
        "SELECT status FROM channel_subscriptions WHERE channel_id = ? AND device_id = ?",
    )
    .bind(&subscribe.channel_id[..])
    .bind(&device_id[..])
    .fetch_one(&mut conn)
    .await
    .expect("subscription status should be queryable");
    assert_eq!(status, crate::storage::SUBSCRIPTION_STATUS_INACTIVE);
    drop(conn);

    ctx.storage
        .ack_private_delivery(device_id, delivery_id)
        .await
        .expect("pending private outbox should be cleared");

    let advanced = ctx
        .storage
        .run_maintenance_cleanup(
            now + 120_000,
            MaintenanceCleanupConfig {
                stale_subscription_cleanup_enabled: true,
                frozen_subscription_ttl_secs: 60,
                soft_deleted_device_cleanup_enabled: true,
                soft_deleted_device_ttl_secs: 60,
                ..MaintenanceCleanupConfig::default()
            },
        )
        .await
        .expect("maintenance cleanup should advance after outbox clears");
    assert_eq!(advanced.frozen_subscriptions_pruned, 1);
}

#[tokio::test]
async fn provider_pull_clears_original_private_outbox_delivery() {
    let ctx = setup_sqlite_storage("provider-pull-original-outbox-cleanup").await;

    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [7; 16];
    let platform = Platform::IOS;
    let provider_token = "ios-provider-token-provider-pull-cleanup-001";
    let original_delivery_id = "delivery-original-private-001";
    let provider_delivery_id = original_delivery_id;

    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id", original_delivery_id);
    let envelope = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("provider pull envelope should encode");
    let message = PrivateMessage {
        payload: envelope.clone().into(),
        size: envelope.len(),
        sent_at: now,
        expires_at: now + 300_000,
    };

    ctx.storage
        .insert_private_message(original_delivery_id, &message)
        .await
        .expect("insert original private payload should succeed");

    let original_entry = PrivateOutboxEntry {
        delivery_id: original_delivery_id.to_string(),
        status: OUTBOX_STATUS_PENDING.to_string(),
        attempts: 0,
        occurred_at: now,
        created_at: now,
        claimed_at: None,
        claimed_by: None,
        claim_generation: 0,
        first_sent_at: None,
        last_attempt_at: None,
        acked_at: None,
        fallback_sent_at: None,
        next_attempt_at: now,
        last_error_code: None,
        last_error_detail: None,
        updated_at: now,
    };
    ctx.storage
        .enqueue_private_outbox(device_id, &original_entry)
        .await
        .expect("enqueue original private outbox should succeed");
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            provider_delivery_id,
            &message,
            platform,
            provider_token,
        )
        .await
        .expect("enqueue provider pull item should succeed");

    let pulled = ctx
        .storage
        .pull_provider_item(device_id, provider_delivery_id, now + 1)
        .await
        .expect("pull provider item should succeed");
    assert!(pulled.is_some());

    let original_outbox_after_pull = ctx
        .storage
        .load_private_outbox_entry(device_id, original_delivery_id)
        .await
        .expect("load original outbox after pull should succeed");
    assert_eq!(
        original_outbox_after_pull
            .expect("consumed linked delivery should retain a tombstone")
            .status,
        OUTBOX_STATUS_ACKED
    );

    let original_payload_after_pull = ctx
        .storage
        .load_private_message(original_delivery_id)
        .await
        .expect("load original payload after pull should succeed");
    assert!(original_payload_after_pull.is_none());
}

#[tokio::test]
async fn provider_pull_linked_cleanup_failure_rolls_back_the_consumption() {
    let ctx = setup_sqlite_storage("provider-pull-linked-cleanup-rollback").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [44; 16];
    let delivery_id = "provider-pull-linked-cleanup-rollback-delivery";
    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id", delivery_id);
    let payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("linked provider payload should encode");
    let message = PrivateMessage {
        size: payload.len(),
        payload: payload.into(),
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("private payload should be inserted");
    ctx.storage
        .enqueue_private_outbox(
            device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now,
            },
        )
        .await
        .expect("private outbox should be inserted");
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "provider-pull-linked-cleanup-rollback-token",
        )
        .await
        .expect("provider pull item should be inserted");

    let mut delivery_conn = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("delivery sidecar connection should succeed");
    sqlx::query(
        "CREATE TRIGGER reject_linked_private_outbox_cleanup \
         BEFORE UPDATE OF status ON private_outbox \
         WHEN OLD.delivery_id = 'provider-pull-linked-cleanup-rollback-delivery' AND NEW.status = 'acked' \
         BEGIN SELECT RAISE(ABORT, 'injected linked cleanup failure'); END",
    )
    .execute(&mut delivery_conn)
    .await
    .expect("failure trigger should be installed");

    assert!(
        ctx.storage
            .pull_provider_item(device_id, delivery_id, now + 1)
            .await
            .is_err(),
        "linked cleanup failure must fail the whole pull transaction"
    );
    let provider_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM provider_pull_queue WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(device_id.as_slice())
    .bind(delivery_id)
    .fetch_one(&mut delivery_conn)
    .await
    .expect("provider queue should remain queryable");
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(1) FROM private_outbox WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(device_id.as_slice())
    .bind(delivery_id)
    .fetch_one(&mut delivery_conn)
    .await
    .expect("private outbox should remain queryable");
    let payload_count: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM private_payloads WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut delivery_conn)
            .await
            .expect("private payload should remain queryable");
    assert_eq!((provider_count, outbox_count, payload_count), (1, 1, 1));
}

#[tokio::test]
async fn provider_pull_candidate_ignores_historical_invalid_platform_metadata() {
    let ctx = setup_sqlite_storage("provider-candidate-invalid-platform").await;
    let device_id: DeviceId = [35; 16];
    let delivery_id = "provider-candidate-invalid-platform-delivery";
    let now = chrono::Utc::now().timestamp_millis();
    let message = PrivateMessage {
        payload: vec![0xff, 0x00, 0x7f].into(),
        size: 3,
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "candidate-invalid-platform-token",
        )
        .await
        .expect("provider candidate fixture should enqueue");
    let mut delivery = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("delivery sidecar mutation connection should succeed");
    sqlx::query(
        "UPDATE provider_pull_queue SET platform = 'future-unsupported-platform' \
         WHERE device_id = ? AND delivery_id = ?",
    )
    .bind(device_id.as_slice())
    .bind(delivery_id)
    .execute(&mut delivery)
    .await
    .expect("historical invalid platform should seed");

    let candidate = ctx
        .storage
        .peek_provider_candidate(device_id, delivery_id, now)
        .await
        .expect("raw candidate lookup must not parse unrelated platform metadata")
        .expect("raw candidate should remain visible");
    assert_eq!(candidate.delivery_id, delivery_id);
    assert_eq!(candidate.payload.as_ref(), message.payload.as_ref());
    assert_eq!(
        ctx.storage
            .discard_invalid_provider_candidates(device_id, std::slice::from_ref(&candidate), now)
            .await
            .expect("exact invalid candidate should delete"),
        1
    );
    assert!(
        ctx.storage
            .peek_provider_candidate(device_id, delivery_id, now)
            .await
            .expect("discarded candidate lookup should succeed")
            .is_none()
    );
}

#[tokio::test]
async fn stale_invalid_provider_candidate_does_not_discard_valid_recache() {
    let ctx = setup_sqlite_storage("provider-invalid-discard-cas").await;
    let device_id: DeviceId = [36; 16];
    let delivery_id = "provider-invalid-discard-cas-delivery";
    let now = chrono::Utc::now().timestamp_millis();
    let mut invalid_data = hashbrown::HashMap::new();
    invalid_data.insert("delivery_id", delivery_id);
    let invalid_payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 2,
        data: invalid_data,
    })
    .expect("unsupported provider payload should encode");
    let invalid = PrivateMessage {
        payload: invalid_payload.clone().into(),
        size: invalid_payload.len(),
        sent_at: now,
        expires_at: now + 60_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &invalid,
            Platform::ANDROID,
            "provider-invalid-discard-cas-token",
        )
        .await
        .expect("invalid provider candidate should enqueue");
    let stale_invalid = ctx
        .storage
        .peek_provider_candidate(device_id, delivery_id, now)
        .await
        .expect("invalid candidate lookup should succeed")
        .expect("invalid candidate should exist");

    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id", delivery_id);
    let valid_payload = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("valid provider payload should encode");
    let mut delivery = SqliteConnection::connect(&ctx.delivery_db_url)
        .await
        .expect("delivery sidecar recache connection should succeed");
    sqlx::query(
        "UPDATE private_payloads SET payload_blob = ?, payload_size = ?, updated_at = ? \
         WHERE delivery_id = ?",
    )
    .bind(&valid_payload)
    .bind(valid_payload.len() as i64)
    .bind(now + 1)
    .bind(delivery_id)
    .execute(&mut delivery)
    .await
    .expect("valid payload recache should succeed");

    assert_eq!(
        ctx.storage
            .discard_invalid_provider_candidates(
                device_id,
                std::slice::from_ref(&stale_invalid),
                now + 1,
            )
            .await
            .expect("stale invalid candidate discard should complete"),
        0,
        "a stale invalid candidate must not delete a valid recache"
    );
    let current = ctx
        .storage
        .peek_provider_candidate(device_id, delivery_id, now + 1)
        .await
        .expect("current candidate lookup should succeed")
        .expect("valid recache must remain queued");
    assert_eq!(current.payload.as_ref(), valid_payload.as_slice());
}

#[tokio::test]
async fn sqlite_provider_finalization_rolls_back_dedupe_when_sender_update_fails() {
    let ctx = setup_sqlite_storage("provider-finalize-mid-transaction-rollback").await;
    let op_id = "provider-finalize-rollback-op";
    let dedupe_key = format!("op:provider-finalize-scope:{op_id}");
    let delivery_id = "provider-finalize-rollback-delivery";
    let now = chrono::Utc::now().timestamp_millis();
    assert!(matches!(
        ctx.storage
            .reserve_op_dedupe_pending(&dedupe_key, delivery_id, now)
            .await
            .expect("reserve provider finalization dedupe"),
        OpDedupeReservation::Reserved | OpDedupeReservation::ReservedSubmission { .. }
    ));
    assert!(
        ctx.storage
            .mark_op_dedupe_finalized(&dedupe_key, delivery_id, DedupeState::ProviderQueued)
            .await
            .expect("mark provider queued before finalization")
    );
    ctx.storage
        .insert_sender_submit_status_if_absent(&SenderSubmitStatusRecord {
            op_id: op_id.to_string(),
            channel_id: [33; 16],
            model: "message".to_string(),
            entity_id: "provider-finalize-rollback-entity".to_string(),
            status: SenderSubmitStatusKind::ProviderQueued,
            dispatch_status: Some("provider_queued".to_string()),
            accepted_at: now,
            updated_at: now,
            expires_at: now + 60_000,
        })
        .await
        .expect("insert provider queued sender status");

    let mut core = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite core trigger connection should succeed");
    sqlx::query(
        "CREATE TRIGGER fail_provider_sender_finalize \
         BEFORE UPDATE ON sender_submit_status \
         WHEN NEW.dispatch_status IN ('provider_success', 'provider_failed') \
         BEGIN SELECT RAISE(ABORT, 'injected sender finalization failure'); END",
    )
    .execute(&mut core)
    .await
    .expect("provider finalization failure trigger should install");

    assert!(
        ctx.storage
            .finalize_provider_dispatch_outcome(&dedupe_key, op_id, delivery_id, true)
            .await
            .is_err(),
        "injected sender update failure must fail the whole finalization"
    );
    let mut dispatch = SqliteConnection::connect(&ctx.dispatch_db_url)
        .await
        .expect("sqlite dispatch verification connection should succeed");
    let dedupe_state: String =
        sqlx::query_scalar("SELECT state FROM dispatch_op_dedupe WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut dispatch)
            .await
            .expect("dedupe state should remain readable after rollback");
    assert_eq!(dedupe_state, DedupeState::ProviderQueued.as_str());
    let sender_status: String =
        sqlx::query_scalar("SELECT status FROM sender_submit_status WHERE op_id = ?")
            .bind(op_id)
            .fetch_one(&mut core)
            .await
            .expect("sender status should remain readable after rollback");
    assert_eq!(
        sender_status,
        SenderSubmitStatusKind::ProviderQueued.as_str()
    );

    sqlx::query("DROP TRIGGER fail_provider_sender_finalize")
        .execute(&mut core)
        .await
        .expect("provider finalization failure trigger should drop");
    ctx.storage
        .finalize_provider_dispatch_outcome(&dedupe_key, op_id, delivery_id, true)
        .await
        .expect("provider finalization should succeed after failure is removed");
    let final_dedupe_state: String =
        sqlx::query_scalar("SELECT state FROM dispatch_op_dedupe WHERE delivery_id = ?")
            .bind(delivery_id)
            .fetch_one(&mut dispatch)
            .await
            .expect("final dedupe state should be readable");
    assert_eq!(final_dedupe_state, DedupeState::Sent.as_str());
}

#[tokio::test]
async fn provider_batch_ack_atomically_clears_linked_private_deliveries() {
    let ctx = setup_sqlite_storage("provider-batch-ack-linked-private-cleanup").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [27; 16];
    let pairs = [
        ("provider-batch-ack-001", "private-original-batch-ack-001"),
        ("provider-batch-ack-002", "private-original-batch-ack-002"),
    ];

    for (provider_delivery_id, original_delivery_id) in pairs {
        let mut data = hashbrown::HashMap::new();
        data.insert("delivery_id", original_delivery_id);
        let envelope = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
            payload_version: 1,
            data,
        })
        .expect("provider pull envelope should encode");
        let message = PrivateMessage {
            payload: envelope.clone().into(),
            size: envelope.len(),
            sent_at: now,
            expires_at: now + 300_000,
        };
        ctx.storage
            .insert_private_message(original_delivery_id, &message)
            .await
            .expect("insert original private payload should succeed");
        ctx.storage
            .enqueue_private_outbox(
                device_id,
                &PrivateOutboxEntry {
                    delivery_id: original_delivery_id.to_string(),
                    status: OUTBOX_STATUS_PENDING.to_string(),
                    attempts: 0,
                    occurred_at: now,
                    created_at: now,
                    claimed_at: None,
                    claimed_by: None,
                    claim_generation: 0,
                    first_sent_at: None,
                    last_attempt_at: None,
                    acked_at: None,
                    fallback_sent_at: None,
                    next_attempt_at: now,
                    last_error_code: None,
                    last_error_detail: None,
                    updated_at: now,
                },
            )
            .await
            .expect("enqueue original private outbox should succeed");
        ctx.storage
            .enqueue_provider_pull_item(
                device_id,
                provider_delivery_id,
                &message,
                Platform::ANDROID,
                "fcm-token-batch-ack-linked-001",
            )
            .await
            .expect("enqueue provider pull item should succeed");
    }

    let ids = pairs
        .iter()
        .map(|(provider_delivery_id, _)| (*provider_delivery_id).to_string())
        .collect::<Vec<_>>();
    let acknowledged = ctx
        .storage
        .ack_provider_items(device_id, &ids, now + 1)
        .await
        .expect("batch ACK should succeed atomically");
    assert_eq!(acknowledged.len(), 2);

    for (provider_delivery_id, original_delivery_id) in pairs {
        assert!(
            ctx.storage
                .peek_provider_item(device_id, provider_delivery_id, now + 2)
                .await
                .expect("provider item lookup should succeed")
                .is_none()
        );
        assert_eq!(
            ctx.storage
                .load_private_outbox_entry(device_id, original_delivery_id)
                .await
                .expect("private outbox lookup should succeed")
                .expect("linked ACK should retain a tombstone")
                .status,
            OUTBOX_STATUS_ACKED
        );
        assert!(
            ctx.storage
                .load_private_message(original_delivery_id)
                .await
                .expect("private payload lookup should succeed")
                .is_none()
        );
    }
}

#[tokio::test]
async fn provider_ack_discards_expired_item_consistently() {
    let ctx = setup_sqlite_storage("provider-ack-expired-consistency").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_id: DeviceId = [28; 16];
    let delivery_id = "provider-ack-expired-001";
    let message = PrivateMessage {
        payload: vec![1, 2, 3].into(),
        size: 3,
        sent_at: now - 2_000,
        expires_at: now - 1,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            "fcm-token-expired-ack-001",
        )
        .await
        .expect("expired fixture should seed");

    let acknowledged = ctx
        .storage
        .ack_provider_item(device_id, delivery_id, now)
        .await
        .expect("expired ACK should succeed idempotently");
    assert!(acknowledged.is_none());
    assert!(
        ctx.storage
            .peek_provider_item(device_id, delivery_id, now + 1)
            .await
            .expect("expired provider item lookup should succeed")
            .is_none(),
        "expired ACK must remove the stale row across every backend"
    );
}

#[tokio::test]
async fn provider_invalid_token_cleanup_unsubscribes_and_clears_private_outbox() {
    let ctx = setup_sqlite_storage("provider-invalid-token-cleanup").await;
    let now = chrono::Utc::now().timestamp_millis();
    let device_key = "provider-invalid-token-cleanup-device";
    let provider_token = "android-provider-token-invalid-cleanup-0000000001";
    let private_device_id = derive_private_device_id(device_key);
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        provider_token,
        "invalid-token-cleanup",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    ctx.storage
        .bind_private_token(private_device_id, Platform::ANDROID, provider_token)
        .await
        .expect("private token binding should succeed");

    let delivery_id = "provider-invalid-token-cleanup-delivery";
    let mut data = hashbrown::HashMap::new();
    data.insert("delivery_id", delivery_id);
    let envelope = postcard::to_allocvec(&TestPrivatePayloadEnvelope {
        payload_version: 1,
        data,
    })
    .expect("private envelope should encode");
    let message = PrivateMessage {
        payload: envelope.clone().into(),
        size: envelope.len(),
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .insert_private_message(delivery_id, &message)
        .await
        .expect("private message should insert");
    ctx.storage
        .enqueue_private_outbox(
            private_device_id,
            &PrivateOutboxEntry {
                delivery_id: delivery_id.to_string(),
                status: OUTBOX_STATUS_PENDING.to_string(),
                attempts: 0,
                occurred_at: now,
                created_at: now,
                claimed_at: None,
                claimed_by: None,
                claim_generation: 0,
                first_sent_at: None,
                last_attempt_at: None,
                acked_at: None,
                fallback_sent_at: None,
                next_attempt_at: now,
                last_error_code: None,
                last_error_detail: None,
                updated_at: now,
            },
        )
        .await
        .expect("private outbox should enqueue");

    let runtime_counters = crate::runtime_counters::RuntimeCounterCollector::spawn_with_mode(
        ctx.storage.clone(),
        false,
        crate::runtime_config::GatewayRuntimeProfile::Small,
    );
    let route_updated_at = ctx
        .storage
        .load_device_routes()
        .await
        .expect("provider routes should load")
        .into_iter()
        .find(|route| route.device_key == device_key)
        .expect("provider route should exist")
        .updated_at;
    crate::delivery_core::execution::provider::cleanup_invalid_provider_token(
        crate::delivery_core::execution::provider::ProviderInvalidTokenCleanup {
            store: &ctx.storage,
            private: None,
            runtime_counters: runtime_counters.as_ref(),
            channel_id: subscribe.channel_id,
            channel_id_text: &crate::value::ChannelId::from(subscribe.channel_id).to_string(),
            device_key,
            platform: Platform::ANDROID,
            device_token: provider_token,
            route_updated_at,
            provider: "FCM",
            correlation_id: "provider-invalid-token-cleanup-test",
        },
    )
    .await;

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, now + 1)
        .await
        .expect("dispatch targets should load");
    assert!(
        targets.is_empty(),
        "invalid provider token cleanup must unsubscribe the provider route from the channel"
    );
    let outbox = ctx
        .storage
        .list_private_outbox(private_device_id, 16)
        .await
        .expect("private outbox should load");
    assert!(
        outbox.is_empty(),
        "invalid provider token cleanup must clear linked private outbox rows"
    );
}

#[tokio::test]
async fn delayed_invalid_token_from_old_a_generation_cannot_retire_new_a_generation() {
    let ctx = setup_sqlite_storage("provider-invalid-token-generation-guard").await;
    let device_key = "provider-invalid-token-generation-device";
    let token_a = "android-provider-token-generation-A-000000000001";
    let token_b = "android-provider-token-generation-B-000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        device_key,
        token_a,
        "invalid-token-generation",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let initial_updated_at = ctx
        .storage
        .load_device_routes()
        .await
        .expect("initial routes should load")
        .into_iter()
        .find(|route| route.device_key == device_key)
        .expect("initial provider route should exist")
        .updated_at;
    ctx.storage
        .persist_device_route_change(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(token_b.to_string()),
            updated_at: initial_updated_at + 1,
        })
        .await
        .expect("A to B route rotation should succeed");
    ctx.storage
        .persist_device_route_change(&DeviceRouteRecordRow {
            device_key: device_key.to_string(),
            platform: Platform::ANDROID.name().to_string(),
            channel_type: Platform::ANDROID.channel_type().to_string(),
            provider_token: Some(token_a.to_string()),
            updated_at: initial_updated_at + 2,
        })
        .await
        .expect("B to new A route rotation should succeed");

    let runtime_counters = crate::runtime_counters::RuntimeCounterCollector::spawn_with_mode(
        ctx.storage.clone(),
        false,
        crate::runtime_config::GatewayRuntimeProfile::Small,
    );
    crate::delivery_core::execution::provider::cleanup_invalid_provider_token(
        crate::delivery_core::execution::provider::ProviderInvalidTokenCleanup {
            store: &ctx.storage,
            private: None,
            runtime_counters: runtime_counters.as_ref(),
            channel_id: subscribe.channel_id,
            channel_id_text: &crate::value::ChannelId::from(subscribe.channel_id).to_string(),
            device_key,
            platform: Platform::ANDROID,
            device_token: token_a,
            route_updated_at: initial_updated_at,
            provider: "FCM",
            correlation_id: "provider-invalid-token-stale-a-generation",
        },
    )
    .await;

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(
            subscribe.channel_id,
            chrono::Utc::now().timestamp_millis() + 1,
        )
        .await
        .expect("dispatch targets should load after stale invalid response");
    assert!(
        targets.iter().any(|target| matches!(
            target,
            DispatchTarget::Provider { provider_token, route_updated_at, .. }
                if provider_token == token_a && *route_updated_at == initial_updated_at + 2
        )),
        "a delayed invalid response for the old A generation must not retire the new A generation; targets={targets:?}"
    );
}

#[tokio::test]
async fn load_device_routes_uses_devices_snapshot_not_channel_subscriptions() {
    let ctx = setup_sqlite_storage("device-routes-semantics").await;
    let token = "android-route-semantics-000000000000000000000000000001";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        "device-routes-semantics-device-key",
        token,
        "route-sem",
        "pw123456",
        Platform::ANDROID,
    )
    .await;

    let routes_before = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes before upsert should succeed");
    assert_eq!(routes_before.len(), 1);

    let fallback_device_id = derive_private_device_id("device-routes-semantics-device-key");
    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    sqlx::query("DELETE FROM devices WHERE device_id = ?")
        .bind(&fallback_device_id[..])
        .execute(&mut conn)
        .await
        .expect("device snapshot delete should succeed");
    let routes_without_devices = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes after device delete should succeed");
    assert!(
        routes_without_devices.is_empty(),
        "subscription rows must not be treated as route state"
    );

    let route = DeviceRouteRecordRow {
        device_key: "5EACA42011AB1F85449757D0A6087705".to_string(),
        platform: "android".to_string(),
        channel_type: "private".to_string(),
        provider_token: None,
        updated_at: chrono::Utc::now().timestamp_millis(),
    };
    ctx.storage
        .upsert_device_route(&route)
        .await
        .expect("upsert route should succeed");

    let routes_after = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes after upsert should succeed");
    assert_eq!(routes_after.len(), 1);
    assert_eq!(routes_after[0].device_key, route.device_key);
    assert_eq!(routes_after[0].platform, route.platform);
    assert_eq!(routes_after[0].channel_type, route.channel_type);

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(subscribe.channel_id, chrono::Utc::now().timestamp_millis())
        .await
        .expect("dispatch targets fetch should succeed");
    assert_eq!(targets.len(), 0);

    let mut conn = SqliteConnection::connect(&ctx.db_url)
        .await
        .expect("sqlite test connection should succeed");
    let route_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(1) FROM devices WHERE route_updated_at IS NOT NULL")
            .fetch_one(&mut conn)
            .await
            .expect("route row count should be queryable");
    let subscription_rows: i64 = sqlx::query_scalar("SELECT COUNT(1) FROM channel_subscriptions")
        .fetch_one(&mut conn)
        .await
        .expect("subscription row count should be queryable");
    assert_eq!(route_rows, 1);
    assert_eq!(subscription_rows, 1);
}

#[tokio::test]
async fn upsert_device_route_coalesces_duplicate_provider_identities() {
    let ctx = setup_sqlite_storage("route-coalesces-duplicate-provider-identities").await;
    let token = "android-token-provider-identity-coalesce-0000001";
    let old_device_key = "provider-identity-old-device-key";
    let subscribe = subscribe_provider_channel_for_test(
        &ctx.storage,
        old_device_key,
        token,
        "provider-identity-old",
        "pw123456",
        Platform::ANDROID,
    )
    .await;
    let channel_id = subscribe.channel_id;
    let old_device_id = derive_private_device_id(old_device_key);
    let now = chrono::Utc::now().timestamp_millis();
    let delivery_id = "delivery-provider-identity-coalesce-001";
    let message = PrivateMessage {
        payload: vec![9, 8, 7, 6].into(),
        size: 4,
        sent_at: now,
        expires_at: now + 300_000,
    };
    ctx.storage
        .enqueue_provider_pull_item(
            old_device_id,
            delivery_id,
            &message,
            Platform::ANDROID,
            token,
        )
        .await
        .expect("old device provider queue enqueue should succeed");

    let new_device_key = "provider-identity-new-device-key";
    let new_route = DeviceRouteRecordRow {
        device_key: new_device_key.to_string(),
        platform: Platform::ANDROID.name().to_string(),
        channel_type: Platform::ANDROID.channel_type().to_string(),
        provider_token: Some(token.to_string()),
        updated_at: now + 1,
    };
    ctx.storage
        .upsert_device_route(&new_route)
        .await
        .expect("new route upsert should coalesce duplicates");

    let routes = ctx
        .storage
        .load_device_routes()
        .await
        .expect("load routes should succeed");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].device_key, new_device_key);

    let old_channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(old_device_key)
        .await
        .expect("list old device subscriptions should succeed");
    assert!(old_channels.is_empty());
    let new_channels = ctx
        .storage
        .list_subscribed_channels_for_device_key(new_device_key)
        .await
        .expect("list new device subscriptions should succeed");
    assert_eq!(new_channels, vec![channel_id]);

    let new_device_id = derive_private_device_id(new_device_key);
    let migrated = ctx
        .storage
        .pull_provider_items(new_device_id, now + 10, 10)
        .await
        .expect("provider queue pull should succeed");
    assert_eq!(migrated.len(), 1);
    assert_eq!(migrated[0].delivery_id, delivery_id);

    let targets = ctx
        .storage
        .list_channel_dispatch_targets(channel_id, now + 10)
        .await
        .expect("dispatch target fetch should succeed");
    assert_eq!(targets.len(), 1);
    match &targets[0] {
        DispatchTarget::Provider { device_key, .. } => {
            assert_eq!(device_key, new_device_key);
        }
        other => panic!("expected provider target after coalescing identities, got {other:?}"),
    }
}
