async fn run_claim_ack_drain(
    state: &PrivateState,
    dispatch: &DispatchChannels,
    _scheduler: &mut FallbackScheduler,
    batch_size: usize,
    max_rounds: usize,
    max_processed_total: usize,
) -> Result<(), crate::Error> {
    if !private_provider_wakeup_pull_enabled() {
        return Ok(());
    }
    let batch_size = batch_size.max(1);
    let max_rounds = max_rounds.max(1);
    let max_processed_total = max_processed_total.max(batch_size);
    let mut processed_total = 0usize;
    for round in 0..max_rounds {
        let online_devices = state.hub.online_device_ids();
        if online_devices.is_empty() {
            break;
        }
        let now = chrono::Utc::now().timestamp();
        let claim_until = now.saturating_add(state.config.ack_timeout_secs.clamp(5, 120) as i64);
        let remaining_budget = max_processed_total.saturating_sub(processed_total);
        if remaining_budget == 0 {
            break;
        }
        let round_budget = batch_size.min(remaining_budget);
        if round_budget == 0 {
            break;
        }

        let mut processed = 0usize;
        let per_device_limit = (round_budget / online_devices.len().max(1)).max(1);
        for device_id in online_devices {
            if processed >= round_budget || processed_total >= max_processed_total {
                break;
            }
            let device_limit = per_device_limit.min(round_budget.saturating_sub(processed));
            if device_limit == 0 {
                break;
            }
            let claimed = state
                .hub
                .claim_due_outbox_for_device(device_id, now, device_limit, claim_until)
                .await?;
            if claimed.is_empty() {
                continue;
            }
            for outbox in claimed {
                processed = processed.saturating_add(1);
                processed_total = processed_total.saturating_add(1);
                run_claimed_fallback_task(state, dispatch, device_id, &outbox, now).await?;
                if processed >= round_budget || processed_total >= max_processed_total {
                    break;
                }
            }
        }

        if processed == 0 {
            break;
        }
        if processed < round_budget {
            break;
        }
        if round + 1 < max_rounds {
            tokio::task::yield_now().await;
        }
    }
    Ok(())
}

async fn resync_fallback_tasks(
    state: &PrivateState,
    scheduler: &mut FallbackScheduler,
    limit: usize,
) -> Result<(), crate::Error> {
    if !private_provider_wakeup_pull_enabled() {
        scheduler.replace_fallback_tasks(std::iter::empty::<(FallbackTaskKey, i64)>());
        return Ok(());
    }
    let online_device_ids: HashSet<DeviceId> = state.hub.online_device_ids().into_iter().collect();
    if online_device_ids.is_empty() {
        scheduler.replace_fallback_tasks(std::iter::empty());
        return Ok(());
    }
    let total_pending = state.hub.count_pending_outbox_total().await?;
    let entries = state.hub.list_due_outbox(i64::MAX, limit).await?;
    let snapshot = entries.into_iter().filter_map(|(device_id, entry)| {
        online_device_ids.contains(&device_id).then_some((
            FallbackTaskKey {
                device_id,
                delivery_id: entry.delivery_id,
            },
            entry.next_attempt_at,
        ))
    });
    if total_pending > limit {
        scheduler.merge_fallback_tasks(snapshot);
    } else {
        scheduler.replace_fallback_tasks(snapshot);
    }
    Ok(())
}

async fn run_maintenance_tick(state: &PrivateState) -> Result<(), crate::Error> {
    const DELIVERY_DEDUPE_RETENTION_SECS: i64 = 7 * 24 * 60 * 60;
    let now = chrono::Utc::now().timestamp();
    let dedupe_before = now - DELIVERY_DEDUPE_RETENTION_SECS;
    let cleanup: MaintenanceCleanupStats = state
        .hub
        .run_maintenance_cleanup(now, dedupe_before)
        .await?;
    if cleanup.private_outbox_pruned > 0
        && let Some(engine) = &state.fallback_tasks
    {
        engine.request_resync();
    }

    let pending_outbox = state.hub.count_pending_outbox_total().await?;
    let target_hot_cache = state.hub.hot_cache_target_for_pending(pending_outbox);
    state.hub.compact_hot_cache(target_hot_cache);
    try_trim_allocator();
    Ok(())
}

async fn seed_fallback_tasks(state: &PrivateState, scheduler: &mut FallbackScheduler) {
    if !private_provider_wakeup_pull_enabled() {
        return;
    }
    let online_device_ids: HashSet<DeviceId> = state.hub.online_device_ids().into_iter().collect();
    if online_device_ids.is_empty() {
        return;
    }
    let total_pending = match state.hub.count_pending_outbox_total().await {
        Ok(value) => value,
        Err(_err) => {
            return;
        }
    };
    if total_pending == 0 {
        return;
    }
    let seed_limit = total_pending.min(200_000);
    let entries = match state.hub.list_due_outbox(i64::MAX, seed_limit).await {
        Ok(value) => value,
        Err(_err) => {
            return;
        }
    };
    let mut seeded = 0usize;
    for (device_id, entry) in entries {
        if !online_device_ids.contains(&device_id) {
            continue;
        }
        scheduler.schedule(
            FallbackTaskKey {
                device_id,
                delivery_id: entry.delivery_id,
            },
            entry.next_attempt_at,
        );
        seeded = seeded.saturating_add(1);
    }
    if seeded > 0 {
        state.metrics.mark_replay_bootstrap_enqueued(seeded);
    }
}

fn unix_secs_to_tokio_instant(unix_secs: i64) -> TokioInstant {
    let now_unix = chrono::Utc::now().timestamp();
    if unix_secs <= now_unix {
        TokioInstant::now()
    } else {
        TokioInstant::now() + Duration::from_secs((unix_secs - now_unix) as u64)
    }
}

fn try_trim_allocator() {}

#[inline]
fn private_provider_wakeup_pull_enabled() -> bool {
    PRIVATE_PROVIDER_WAKEUP_PULL_ENABLED
}

async fn run_claimed_fallback_task(
    state: &PrivateState,
    dispatch: &DispatchChannels,
    device_id: DeviceId,
    outbox: &PrivateOutboxEntry,
    now: i64,
) -> Result<(), crate::Error> {
    let Some(message) = state
        .hub
        .load_private_message(outbox.delivery_id.as_str())
        .await?
    else {
        drop_fallback_delivery(
            state,
            device_id,
            outbox.delivery_id.as_str(),
            "missing_private_message",
        )
        .await?;
        return Ok(());
    };
    if message.expires_at <= now {
        drop_fallback_delivery(
            state,
            device_id,
            outbox.delivery_id.as_str(),
            "message_expired",
        )
        .await?;
        return Ok(());
    }

    let envelope: crate::private::protocol::PrivatePayloadEnvelope =
        match postcard::from_bytes(&message.payload) {
            Ok(value) => value,
            Err(_) => {
                drop_fallback_delivery(
                    state,
                    device_id,
                    outbox.delivery_id.as_str(),
                    "invalid_payload_envelope",
                )
                .await?;
                return Ok(());
            }
        };
    if envelope.payload_version != crate::private::protocol::PRIVATE_PAYLOAD_VERSION_V1 {
        drop_fallback_delivery(
            state,
            device_id,
            outbox.delivery_id.as_str(),
            "unsupported_payload_version",
        )
        .await?;
        return Ok(());
    }
    let data = envelope.data;
    let channel_id_raw = match data.get("channel_id").map(String::as_str) {
        Some(value) => value,
        None => {
            drop_fallback_delivery(
                state,
                device_id,
                outbox.delivery_id.as_str(),
                "payload_channel_missing",
            )
            .await?;
            return Ok(());
        }
    };
    let channel_id = match crate::api::parse_channel_id(channel_id_raw) {
        Ok(value) => value,
        Err(_) => {
            drop_fallback_delivery(
                state,
                device_id,
                outbox.delivery_id.as_str(),
                "payload_channel_invalid",
            )
            .await?;
            return Ok(());
        }
    };

    if !should_attempt_fallback_for_device(state.hub.is_online(device_id)) {
        return Ok(());
    }

    let Some(target) = resolve_system_target(state, channel_id, device_id).await else {
        return Ok(());
    };

    if should_drop_by_attempt_budget(state, outbox) {
        drop_fallback_delivery(
            state,
            device_id,
            outbox.delivery_id.as_str(),
            "max_attempts_exhausted",
        )
        .await?;
        return Ok(());
    }

    let wakeup_data = build_wakeup_data(&data);
    let ttl = data.get("ttl").and_then(|value| value.parse::<i64>().ok());
    let ttl_seconds = ttl.and_then(|expires_at| {
        let seconds = (expires_at - now).max(0);
        u32::try_from(seconds).ok()
    });
    let sent = match target.platform {
        Platform::ANDROID => {
            let correlation_id: Arc<str> = Arc::from(outbox.delivery_id.clone());
            let payload = Arc::new(FcmPayload::new(
                SharedStringMap::from(wakeup_data.clone()),
                "HIGH",
                ttl_seconds,
            ));
            let body = match payload.encoded_body(target.token.as_ref()) {
                Ok(body) => body,
                Err(_) => return Ok(()),
            };
            dispatch
                .try_send_fcm(FcmJob {
                    channel_id,
                    correlation_id: correlation_id.clone(),
                    delivery_id: correlation_id,
                    device_token: target.token,
                    direct_payload: Arc::clone(&payload),
                    direct_body: Arc::clone(&body),
                    wakeup_payload: Some(Arc::clone(&payload)),
                    wakeup_body: Some(body),
                    initial_path: crate::dispatch::ProviderDeliveryPath::WakeupPull,
                    wakeup_payload_within_limit: true,
                    private_wakeup: None,
                })
                .is_ok()
        }
        Platform::WINDOWS => {
            let correlation_id: Arc<str> = Arc::from(outbox.delivery_id.clone());
            let payload = Arc::new(WnsPayload::new(
                SharedStringMap::from(wakeup_data.clone()),
                "high",
                ttl_seconds,
            ));
            dispatch
                .try_send_wns(WnsJob {
                    channel_id,
                    correlation_id: correlation_id.clone(),
                    delivery_id: correlation_id,
                    device_token: target.token,
                    direct_payload: Arc::clone(&payload),
                    wakeup_payload: Some(Arc::clone(&payload)),
                    initial_path: crate::dispatch::ProviderDeliveryPath::WakeupPull,
                    wakeup_payload_within_limit: true,
                    private_wakeup: None,
                })
                .is_ok()
        }
        _ => {
            let correlation_id: Arc<str> = Arc::from(outbox.delivery_id.clone());
            let collapse_id: Arc<str> = Arc::from(format!("private-wakeup:{channel_id_raw}"));
            let payload = Arc::new(ApnsPayload::wakeup(
                Some("You have a new notification.".to_string()),
                Some(channel_id_raw.to_string()),
                ttl,
                SharedStringMap::from(wakeup_data.clone()),
            ));
            dispatch
                .try_send_apns(ApnsJob {
                    channel_id,
                    correlation_id: correlation_id.clone(),
                    delivery_id: correlation_id,
                    device_token: target.token,
                    platform: target.platform,
                    direct_payload: Arc::clone(&payload),
                    wakeup_payload: Some(Arc::clone(&payload)),
                    initial_path: crate::dispatch::ProviderDeliveryPath::WakeupPull,
                    wakeup_payload_within_limit: true,
                    private_wakeup: None,
                    collapse_id: Some(collapse_id),
                })
                .is_ok()
        }
    };

    if sent {
        let next_attempt_at = now.saturating_add(state.config.ack_timeout_secs.max(1) as i64);
        let _ = state
            .mark_fallback_sent(device_id, outbox.delivery_id.as_str(), next_attempt_at)
            .await;
        state.metrics.mark_fallback_tick(1, 1, 0, 0);
        return Ok(());
    }

    schedule_fallback_retry(state, device_id, outbox, now, 0, true).await?;
    Ok(())
}

async fn schedule_fallback_retry(
    state: &PrivateState,
    device_id: DeviceId,
    outbox: &PrivateOutboxEntry,
    now: i64,
    sent: usize,
    enforce_attempt_budget: bool,
) -> Result<i64, crate::Error> {
    let next_attempt = outbox.attempts.saturating_add(1);
    if should_drop_by_next_attempt(state, next_attempt, enforce_attempt_budget) {
        drop_fallback_delivery(
            state,
            device_id,
            outbox.delivery_id.as_str(),
            "max_attempts_exhausted",
        )
        .await?;
        return Ok(now);
    }
    let backoff_base = state.config.ack_timeout_secs.max(1);
    let exp = next_attempt.saturating_sub(1).min(8);
    let mut delay_secs = backoff_base.saturating_mul(1u64 << exp);
    delay_secs = delay_secs.min(state.config.fallback_max_backoff_secs.max(backoff_base));
    let retry_at = now + delay_secs as i64;
    let _ = state
        .defer_fallback_retry(device_id, outbox.delivery_id.as_str(), retry_at)
        .await;
    state.metrics.mark_fallback_tick(1, sent, 1, 0);
    Ok(retry_at)
}

fn should_drop_by_attempt_budget(state: &PrivateState, outbox: &PrivateOutboxEntry) -> bool {
    should_drop_by_next_attempt(state, outbox.attempts, true)
}

fn should_drop_by_next_attempt(
    state: &PrivateState,
    next_attempt: u32,
    enforce_attempt_budget: bool,
) -> bool {
    should_drop_retry_attempt(
        state.config.fallback_max_attempts,
        next_attempt,
        enforce_attempt_budget,
    )
}

fn should_attempt_fallback_for_device(is_online: bool) -> bool {
    is_online
}

fn should_drop_retry_attempt(
    max_attempts: u32,
    next_attempt: u32,
    enforce_attempt_budget: bool,
) -> bool {
    if !enforce_attempt_budget {
        return false;
    }
    max_attempts > 0 && next_attempt >= max_attempts
}

async fn drop_fallback_delivery(
    state: &PrivateState,
    device_id: DeviceId,
    delivery_id: &str,
    _reason: &str,
) -> Result<(), crate::Error> {
    let _ = state.drop_terminal_delivery(device_id, delivery_id).await?;
    state.metrics.mark_fallback_tick(1, 0, 0, 1);
    Ok(())
}

#[derive(Default)]
struct FallbackScheduler {
    heap: BinaryHeap<FallbackTaskEntry>,
    active: HashMap<SchedulerTaskKey, (i64, u64)>,
    fallback_depth: usize,
    next_sequence: u64,
}

impl FallbackScheduler {
    fn apply(&mut self, cmd: FallbackTaskCommand) {
        match cmd {
            FallbackTaskCommand::Schedule {
                key,
                due_at_unix_secs,
            } => self.schedule(key, due_at_unix_secs),
            FallbackTaskCommand::Cancel { key } => {
                if self
                    .active
                    .remove(&SchedulerTaskKey::Fallback(key))
                    .is_some()
                {
                    self.fallback_depth = self.fallback_depth.saturating_sub(1);
                }
                self.maybe_compact();
            }
        }
    }

    fn schedule(&mut self, key: FallbackTaskKey, due_at_unix_secs: i64) {
        self.schedule_task(SchedulerTaskKey::Fallback(key), due_at_unix_secs);
    }

    fn schedule_maintenance(&mut self, due_at_unix_secs: i64) {
        self.schedule_task(SchedulerTaskKey::Maintenance, due_at_unix_secs);
    }

    fn replace_fallback_tasks<I>(&mut self, entries: I)
    where
        I: IntoIterator<Item = (FallbackTaskKey, i64)>,
    {
        self.active
            .retain(|key, _| matches!(key, SchedulerTaskKey::Maintenance));
        self.fallback_depth = 0;
        for (key, due_at_unix_secs) in entries {
            self.schedule(key, due_at_unix_secs);
        }
        self.compact();
    }

    fn merge_fallback_tasks<I>(&mut self, entries: I)
    where
        I: IntoIterator<Item = (FallbackTaskKey, i64)>,
    {
        for (key, due_at_unix_secs) in entries {
            self.schedule(key, due_at_unix_secs);
        }
        self.compact();
    }

    fn schedule_task(&mut self, key: SchedulerTaskKey, due_at_unix_secs: i64) {
        if self
            .active
            .get(&key)
            .is_some_and(|(existing_due, _)| *existing_due == due_at_unix_secs)
        {
            return;
        }
        self.next_sequence = self.next_sequence.saturating_add(1);
        let sequence = self.next_sequence;
        let is_fallback = matches!(key, SchedulerTaskKey::Fallback(_));
        let previous = self
            .active
            .insert(key.clone(), (due_at_unix_secs, sequence));
        if is_fallback && previous.is_none() {
            self.fallback_depth = self.fallback_depth.saturating_add(1);
        }
        self.heap.push(FallbackTaskEntry {
            due_at_unix_secs,
            sequence,
            key,
        });
        self.maybe_compact();
    }

    fn next_due_unix_secs(&mut self) -> Option<i64> {
        self.prune_stale();
        self.heap.peek().map(|entry| entry.due_at_unix_secs)
    }

    fn pop_due(&mut self, now: i64, max_batch: usize) -> Vec<(SchedulerTaskKey, i64)> {
        let mut out = Vec::new();
        self.prune_stale();
        while out.len() < max_batch {
            let Some(top) = self.heap.peek() else {
                break;
            };
            if top.due_at_unix_secs > now {
                break;
            }
            let top = self.heap.pop().expect("heap peeked");
            let Some((active_due, active_seq)) = self.active.get(&top.key).copied() else {
                continue;
            };
            if active_seq != top.sequence || active_due != top.due_at_unix_secs {
                continue;
            }
            if self.active.remove(&top.key).is_some()
                && matches!(top.key, SchedulerTaskKey::Fallback(_))
            {
                self.fallback_depth = self.fallback_depth.saturating_sub(1);
            }
            out.push((top.key, top.due_at_unix_secs));
        }
        self.maybe_compact();
        out
    }

    fn prune_stale(&mut self) {
        while let Some(top) = self.heap.peek() {
            let Some((active_due, active_seq)) = self.active.get(&top.key).copied() else {
                self.heap.pop();
                continue;
            };
            if active_seq != top.sequence || active_due != top.due_at_unix_secs {
                self.heap.pop();
                continue;
            }
            break;
        }
    }

    fn depth(&self) -> usize {
        self.fallback_depth
    }

    fn maybe_compact(&mut self) {
        let active_len = self.active.len();
        let heap_len = self.heap.len();
        if heap_len < FALLBACK_SCHEDULER_COMPACT_MIN_HEAP {
            return;
        }
        let stale = heap_len.saturating_sub(active_len);
        if stale < FALLBACK_SCHEDULER_COMPACT_MIN_STALE {
            return;
        }
        if heap_len
            <= active_len
                .saturating_mul(FALLBACK_SCHEDULER_COMPACT_RATIO)
                .max(FALLBACK_SCHEDULER_COMPACT_MIN_HEAP)
        {
            return;
        }
        self.compact();
    }

    fn compact(&mut self) {
        let mut rebuilt = BinaryHeap::with_capacity(self.active.len().saturating_add(8));
        for (key, (due_at_unix_secs, sequence)) in &self.active {
            rebuilt.push(FallbackTaskEntry {
                due_at_unix_secs: *due_at_unix_secs,
                sequence: *sequence,
                key: key.clone(),
            });
        }
        rebuilt.shrink_to_fit();
        self.heap = rebuilt;
        if self.active.capacity() > self.active.len().saturating_mul(4).saturating_add(256) {
            self.active.shrink_to_fit();
        }
    }
}

struct SystemTarget {
    platform: Platform,
    token: Arc<str>,
}

async fn resolve_system_target(
    state: &PrivateState,
    channel_id: [u8; 16],
    device_id: DeviceId,
) -> Option<SystemTarget> {
    state.resolve_system_target(channel_id, device_id).await
}

fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::ANDROID => "android",
        Platform::WINDOWS => "windows",
        Platform::IOS => "ios",
        Platform::MACOS => "macos",
        Platform::WATCHOS => "watchos",
    }
}

fn new_resume_token() -> String {
    format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    )
}

fn adaptive_retransmit_timeout(base: Duration, rtt_ewma_ms: Option<f64>) -> Duration {
    let base_ms = base.as_millis() as f64;
    let adaptive_ms = rtt_ewma_ms
        .map(|rtt| (rtt * 4.0).clamp(1500.0, 30_000.0))
        .unwrap_or(base_ms);
    let timeout_ms = adaptive_ms.max(base_ms).max(500.0);
    Duration::from_millis(timeout_ms as u64)
}
