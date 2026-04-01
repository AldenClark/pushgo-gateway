
pub struct PrivateHub {
    store: Storage,
    presence: DashMap<DeviceId, Presence>,
    grace_window: Duration,
    resume_ttl: Duration,
    ack_timeout_secs: i64,
    max_pending_per_device: usize,
    global_max_pending: usize,
    hot_cache_capacity: usize,
    retransmit_window: Duration,
    retransmit_max_per_window: u32,
    retransmit_max_per_tick: usize,
    retransmit_max_retries: u8,
    hot_messages: DashMap<String, PrivateMessage>,
    hot_order: Mutex<VecDeque<String>>,
    resume_state: DashMap<DeviceId, ResumeState>,
}

#[derive(Debug, Clone)]
struct Presence {
    quic_active: Option<ActiveConn>,
    tcp_active: Option<ActiveConn>,
    wss_active: Option<ActiveConn>,
    draining: Vec<DrainingConn>,
}

#[derive(Debug, Clone)]
struct ActiveConn {
    conn_id: u64,
    sender: Sender<protocol::DeliverEnvelope>,
}

#[derive(Debug, Clone)]
struct DrainingConn {
    conn_id: u64,
    #[allow(dead_code)]
    sender: Sender<protocol::DeliverEnvelope>,
    delivery_until: Instant,
    drain_until: Instant,
}

impl Presence {
    fn slot_mut(&mut self, transport: TransportKind) -> &mut Option<ActiveConn> {
        match transport {
            TransportKind::Quic => &mut self.quic_active,
            TransportKind::Tcp => &mut self.tcp_active,
            TransportKind::Wss => &mut self.wss_active,
        }
    }

    fn active_conn_ids(&self) -> [Option<u64>; 3] {
        [
            self.quic_active.as_ref().map(|active| active.conn_id),
            self.tcp_active.as_ref().map(|active| active.conn_id),
            self.wss_active.as_ref().map(|active| active.conn_id),
        ]
    }

    fn delivery_senders(&self, now: Instant) -> Vec<Sender<protocol::DeliverEnvelope>> {
        let mut senders = Vec::with_capacity(3 + self.draining.len());
        if let Some(active) = self.quic_active.as_ref() {
            senders.push(active.sender.clone());
        }
        if let Some(active) = self.tcp_active.as_ref() {
            senders.push(active.sender.clone());
        }
        if let Some(active) = self.wss_active.as_ref() {
            senders.push(active.sender.clone());
        }
        for draining in &self.draining {
            if draining.delivery_until > now {
                senders.push(draining.sender.clone());
            }
        }
        senders
    }

    fn has_active(&self) -> bool {
        self.quic_active.is_some() || self.tcp_active.is_some() || self.wss_active.is_some()
    }
}

#[derive(Debug, Clone)]
struct ResumeInflight {
    delivery: protocol::DeliverEnvelope,
    sent_at: Instant,
    retries: u8,
}

#[derive(Debug, Clone)]
struct ResumeState {
    token: String,
    next_seq: u64,
    inflight: BTreeMap<u64, ResumeInflight>,
    rtt_ewma_ms: Option<f64>,
    retransmit_window_started: Instant,
    retransmit_in_window: u32,
    updated_at: Instant,
}

impl ResumeState {
    fn fresh(now: Instant) -> Self {
        Self {
            token: Self::new_token(),
            next_seq: 1,
            inflight: BTreeMap::new(),
            rtt_ewma_ms: None,
            retransmit_window_started: now,
            retransmit_in_window: 0,
            updated_at: now,
        }
    }

    fn new_token() -> String {
        format!(
            "{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        )
    }

    fn adaptive_retransmit_timeout(&self, ack_timeout: Duration) -> Duration {
        let base_ms = ack_timeout.as_millis() as f64;
        let adaptive_ms = self
            .rtt_ewma_ms
            .map(|rtt| (rtt * 4.0).clamp(1500.0, 30_000.0))
            .unwrap_or(base_ms);
        let timeout_ms = adaptive_ms.max(base_ms).max(500.0);
        Duration::from_millis(timeout_ms as u64)
    }

    fn reset(&mut self, now: Instant) {
        *self = Self::fresh(now);
    }

    fn ack_up_to(&mut self, last_acked_seq: u64, now: Instant) -> Vec<String> {
        if last_acked_seq == 0 {
            self.updated_at = now;
            return Vec::new();
        }
        let acked: Vec<u64> = self
            .inflight
            .iter()
            .filter_map(|(seq, _)| (*seq <= last_acked_seq).then_some(*seq))
            .collect();
        let mut acked_delivery_ids = Vec::with_capacity(acked.len());
        for seq in acked {
            if let Some(inflight) = self.inflight.remove(&seq) {
                acked_delivery_ids.push(inflight.delivery.delivery_id);
            }
        }
        self.updated_at = now;
        acked_delivery_ids
    }

    fn track_outbound(
        &mut self,
        envelope: protocol::DeliverEnvelope,
        now: Instant,
    ) -> (u64, protocol::DeliverEnvelope) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1).max(1);
        self.inflight.insert(
            seq,
            ResumeInflight {
                delivery: envelope.clone(),
                sent_at: now,
                retries: 0,
            },
        );
        self.updated_at = now;
        (seq, envelope)
    }

    fn mark_sent(&mut self, seq: u64, now: Instant) {
        if let Some(inflight) = self.inflight.get_mut(&seq) {
            inflight.sent_at = now;
            self.updated_at = now;
        }
    }

    fn ack_by_seq(
        &mut self,
        seq: u64,
        expected_delivery_id: Option<&str>,
        now: Instant,
    ) -> Option<String> {
        let inflight = self.inflight.get(&seq)?;
        if let Some(expected) = expected_delivery_id
            && inflight.delivery.delivery_id != expected
        {
            return None;
        }
        let inflight = self.inflight.remove(&seq)?;
        let rtt_ms = now.duration_since(inflight.sent_at).as_secs_f64() * 1000.0;
        let ewma = match self.rtt_ewma_ms {
            Some(prev) => (0.8 * prev) + (0.2 * rtt_ms),
            None => rtt_ms,
        };
        self.rtt_ewma_ms = Some(ewma);
        self.updated_at = now;
        Some(inflight.delivery.delivery_id)
    }

    fn inflight_snapshot(&self) -> Vec<(u64, protocol::DeliverEnvelope)> {
        self.inflight
            .iter()
            .map(|(seq, state)| (*seq, state.delivery.clone()))
            .collect()
    }

    fn next_retransmit_due_in(
        &self,
        now: Instant,
        ack_timeout: Duration,
        retransmit_window: Duration,
        retransmit_max_per_window: u32,
        retransmit_max_retries: u8,
    ) -> Option<Duration> {
        let adaptive_timeout = self.adaptive_retransmit_timeout(ack_timeout);

        let window_wait = if self.retransmit_in_window >= retransmit_max_per_window {
            let window_end = self.retransmit_window_started + retransmit_window;
            Some(window_end.saturating_duration_since(now))
        } else {
            None
        };

        let mut due_wait = window_wait;
        for state in self.inflight.values() {
            if state.retries >= retransmit_max_retries {
                continue;
            }
            let due_at = state.sent_at + adaptive_timeout;
            let wait = due_at.saturating_duration_since(now);
            due_wait = Some(match due_wait {
                Some(current) => current.min(wait),
                None => wait,
            });
        }
        due_wait
    }

    fn collect_retransmit_due(
        &mut self,
        now: Instant,
        ack_timeout: Duration,
        retransmit_window: Duration,
        retransmit_max_per_window: u32,
        retransmit_max_per_tick: usize,
        retransmit_max_retries: u8,
    ) -> Vec<(u64, protocol::DeliverEnvelope)> {
        if now.duration_since(self.retransmit_window_started) >= retransmit_window {
            self.retransmit_window_started = now;
            self.retransmit_in_window = 0;
        }
        let adaptive_timeout = self.adaptive_retransmit_timeout(ack_timeout);
        let mut out = Vec::new();
        let mut retransmit_in_window = self.retransmit_in_window;
        for (seq, state) in &mut self.inflight {
            if out.len() >= retransmit_max_per_tick {
                break;
            }
            if retransmit_in_window >= retransmit_max_per_window {
                break;
            }
            if now.duration_since(state.sent_at) >= adaptive_timeout {
                if state.retries >= retransmit_max_retries {
                    continue;
                }
                state.sent_at = now;
                state.retries = state.retries.saturating_add(1);
                retransmit_in_window = retransmit_in_window.saturating_add(1);
                out.push((*seq, state.delivery.clone()));
            }
        }
        self.retransmit_in_window = retransmit_in_window;
        if !out.is_empty() {
            self.updated_at = now;
        }
        out
    }

    fn drop_exhausted(
        &mut self,
        now: Instant,
        ack_timeout: Duration,
        retransmit_max_retries: u8,
    ) -> usize {
        let adaptive_timeout = self.adaptive_retransmit_timeout(ack_timeout);
        let stale: Vec<u64> = self
            .inflight
            .iter()
            .filter_map(|(seq, state)| {
                if state.retries >= retransmit_max_retries
                    && now.duration_since(state.sent_at) >= adaptive_timeout
                {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();
        for seq in &stale {
            self.inflight.remove(seq);
        }
        if !stale.is_empty() {
            self.updated_at = now;
        }
        stale.len()
    }
}

#[derive(Debug, Clone)]
pub struct ResumeHandshake {
    pub resume_token: String,
    pub acked_delivery_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    Active,
    Draining,
    Stale,
}
