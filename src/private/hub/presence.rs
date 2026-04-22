impl PrivateHub {
    fn compute_draining_delivery_window(&self, device_id: DeviceId) -> Duration {
        let min_ms = PRIVATE_DRAINING_DELIVERY_WINDOW_MIN.as_millis() as u64;
        let max_ms = PRIVATE_DRAINING_DELIVERY_WINDOW_MAX.as_millis() as u64;
        let default_ms = PRIVATE_DRAINING_DELIVERY_WINDOW_DEFAULT.as_millis() as u64;
        let computed_ms = self
            .with_resume_state(device_id, |entry| entry.rtt_ewma_ms)
            .flatten()
            .map(|rtt_ms| {
                (rtt_ms * PRIVATE_DRAINING_DELIVERY_WINDOW_RTT_MULTIPLIER
                    + PRIVATE_DRAINING_DELIVERY_WINDOW_RTT_PADDING_MS)
                    .round() as u64
            })
            .unwrap_or(default_ms)
            .clamp(min_ms, max_ms);
        Duration::from_millis(computed_ms)
    }

    pub fn new(store: Storage, config: &PrivateConfig) -> Self {
        PrivateHub {
            store,
            presence: DashMap::new(),
            grace_window: Duration::from_secs(config.grace_window_secs),
            resume_ttl: Duration::from_secs(config.session_ttl_secs.max(60) as u64),
            ack_timeout_secs: config.ack_timeout_secs.max(1) as i64,
            max_pending_per_device: config.max_pending_per_device,
            global_max_pending: config.global_max_pending,
            hot_cache_capacity: config.hot_cache_capacity.max(1),
            retransmit_window: Duration::from_secs(config.retransmit_window_secs.max(1)),
            retransmit_max_per_window: config.retransmit_max_per_window.max(1),
            retransmit_max_per_tick: config.retransmit_max_per_tick.max(1),
            retransmit_max_retries: config.retransmit_max_retries.max(1),
            hot_messages: DashMap::new(),
            hot_order: Mutex::new(VecDeque::new()),
            resume_state: DashMap::new(),
            enqueue_gate: tokio::sync::Mutex::new(()),
        }
    }

    pub fn store(&self) -> &Storage {
        &self.store
    }

    pub fn encode_device_id(device_id: DeviceId) -> String {
        encode_lower_hex_128(&device_id)
    }

    pub fn decode_device_id(raw: &str) -> Result<DeviceId, crate::util::HexDecodeError> {
        decode_lower_hex_128(raw)
    }

    pub(crate) fn register_connection(
        &self,
        device_id: DeviceId,
        conn_id: u64,
        transport: TransportKind,
        sender: Sender<protocol::DeliverEnvelope>,
    ) -> RegisterConnectionOutcome {
        let now = Instant::now();
        let mut superseded_conn_id = None;
        self.presence
            .entry(device_id)
            .and_modify(|presence| {
                presence.draining.retain(|item| item.drain_until > now);
                let slot = presence.slot_mut(transport);
                if let Some(previous) = slot.replace(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }) {
                    let delivery_window = self
                        .compute_draining_delivery_window(device_id)
                        .min(self.grace_window);
                    presence.draining.push(DrainingConn {
                        conn_id: previous.conn_id,
                        sender: previous.sender,
                        delivery_until: now + delivery_window,
                        drain_until: now + self.grace_window,
                    });
                    superseded_conn_id = Some(previous.conn_id);
                    const MAX_DRAINING_CONN: usize = 16;
                    if presence.draining.len() > MAX_DRAINING_CONN {
                        let overflow = presence.draining.len() - MAX_DRAINING_CONN;
                        presence.draining.drain(0..overflow);
                    }
                }
            })
            .or_insert_with(|| Presence {
                quic_active: matches!(transport, TransportKind::Quic).then_some(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }),
                tcp_active: matches!(transport, TransportKind::Tcp).then_some(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }),
                wss_active: matches!(transport, TransportKind::Wss).then_some(ActiveConn {
                    conn_id,
                    sender: sender.clone(),
                }),
                draining: Vec::new(),
            });
        RegisterConnectionOutcome { superseded_conn_id }
    }

    pub fn collapse_draining_delivery_window_if_active(&self, device_id: DeviceId, conn_id: u64) {
        if let Some(mut presence) = self.presence.get_mut(&device_id) {
            let is_active = presence
                .active_conn_ids()
                .into_iter()
                .flatten()
                .any(|active_id| active_id == conn_id);
            if !is_active {
                return;
            }
            let now = Instant::now();
            for draining in &mut presence.draining {
                draining.delivery_until = now;
            }
        }
    }

    pub fn connection_mode(&self, device_id: DeviceId, conn_id: u64) -> ConnectionMode {
        let Some(presence) = self.presence.get(&device_id) else {
            return ConnectionMode::Stale;
        };
        if presence
            .active_conn_ids()
            .into_iter()
            .flatten()
            .any(|id| id == conn_id)
        {
            return ConnectionMode::Active;
        }
        let now = Instant::now();
        for draining in &presence.draining {
            if draining.conn_id == conn_id {
                if draining.drain_until > now {
                    return ConnectionMode::Draining;
                }
                return ConnectionMode::Stale;
            }
        }
        ConnectionMode::Stale
    }

    pub fn is_online(&self, device_id: DeviceId) -> bool {
        self.presence
            .get(&device_id)
            .map(|presence| presence.has_active())
            .unwrap_or(false)
    }

    pub fn online_device_ids(&self) -> Vec<DeviceId> {
        self.presence
            .iter()
            .filter_map(|entry| entry.value().has_active().then_some(*entry.key()))
            .collect()
    }

    pub fn sweep_draining(&self, device_id: DeviceId) {
        let mut remove_presence = false;
        if let Some(mut entry) = self.presence.get_mut(&device_id) {
            let now = Instant::now();
            entry.draining.retain(|item| item.drain_until > now);
            remove_presence = !entry.has_active() && entry.draining.is_empty();
        }
        if remove_presence {
            self.presence.remove(&device_id);
        }
    }

    pub fn unregister_connection(&self, device_id: DeviceId, conn_id: u64) {
        let mut remove_presence = false;
        if let Some(mut entry) = self.presence.get_mut(&device_id) {
            if entry
                .quic_active
                .as_ref()
                .is_some_and(|active| active.conn_id == conn_id)
            {
                entry.quic_active = None;
            }
            if entry
                .tcp_active
                .as_ref()
                .is_some_and(|active| active.conn_id == conn_id)
            {
                entry.tcp_active = None;
            }
            if entry
                .wss_active
                .as_ref()
                .is_some_and(|active| active.conn_id == conn_id)
            {
                entry.wss_active = None;
            }
            entry.draining.retain(|item| item.conn_id != conn_id);
            if !entry.has_active() && entry.draining.is_empty() {
                remove_presence = true;
            }
        }
        if remove_presence {
            self.presence.remove(&device_id);
        }
    }
    pub async fn deliver_to_device(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> bool {
        if let Some(presence) = self.presence.get(&device_id) {
            let senders = presence.delivery_senders(Instant::now());
            drop(presence);
            let mut delivered = false;
            for sender in senders {
                if sender.send_async(envelope.clone()).await.is_ok() {
                    delivered = true;
                }
            }
            return delivered;
        }
        false
    }

    pub fn try_deliver_to_device(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> bool {
        if let Some(presence) = self.presence.get(&device_id) {
            let senders = presence.delivery_senders(Instant::now());
            drop(presence);
            let mut delivered = false;
            for sender in senders {
                if sender.try_send(envelope.clone()).is_ok() {
                    delivered = true;
                }
            }
            return delivered;
        }
        false
    }
}
