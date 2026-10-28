impl PrivateHub {
    pub(crate) fn resume_token_matches(&self, device_id: DeviceId, token: &str) -> bool {
        self.with_resume_state(device_id, |state| state.token == token)
            .unwrap_or(false)
    }

    fn ensure_resume_state_mut<R>(
        &self,
        device_id: DeviceId,
        now: Instant,
        f: impl FnOnce(&mut ResumeState) -> R,
    ) -> R {
        // Check only this device on the send/handshake path. Global expiry is
        // reclaimed by the existing maintenance owner, not by every delivery.
        // Read presence before taking a resume shard: registration takes the
        // presence shard before consulting resume state for its drain window.
        let online = self.is_online(device_id);
        let mut entry = self
            .resume_state
            .entry(device_id)
            .or_insert_with(|| ResumeState::fresh(now));
        if !online && now.saturating_duration_since(entry.updated_at) >= self.resume_ttl {
            entry.reset(now);
        }
        f(&mut entry)
    }

    fn with_resume_state_mut<R>(
        &self,
        device_id: DeviceId,
        f: impl FnOnce(&mut ResumeState) -> R,
    ) -> Option<R> {
        let mut entry = self.resume_state.get_mut(&device_id)?;
        Some(f(&mut entry))
    }

    fn with_resume_state<R>(
        &self,
        device_id: DeviceId,
        f: impl FnOnce(&ResumeState) -> R,
    ) -> Option<R> {
        let entry = self.resume_state.get(&device_id)?;
        Some(f(&entry))
    }

    pub async fn start_or_resume_session(
        &self,
        device_id: DeviceId,
        client_resume_token: Option<&str>,
        last_acked_seq: u64,
    ) -> ResumeHandshake {
        let now = Instant::now();
        let incoming = client_resume_token
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or_default();
        let mut reset_applied = false;
        // This legacy field is a maximum observed transport sequence, not proof
        // that every lower delivery was persisted. Gaps and concurrent sockets
        // are valid. Only an explicit per-delivery ACK may terminalize work.
        let resume_token = self.ensure_resume_state_mut(device_id, now, |entry| {
            let token_mismatch = incoming.is_empty() || incoming != entry.token;
            if token_mismatch {
                entry.reset(now);
                reset_applied = true;
            }
            entry.updated_at = now;
            entry.token.clone()
        });
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.resume_session_started",
            device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
            reset_applied = (reset_applied),
            ignored_ack_hint = (last_acked_seq)
        );

        ResumeHandshake { resume_token }
    }

    pub fn track_outbound_delivery(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> (u64, protocol::DeliverEnvelope) {
        let now = Instant::now();
        self.ensure_resume_state_mut(device_id, now, |entry| entry.track_outbound(envelope, now))
    }

    pub fn track_sent_outbound(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> (u64, protocol::DeliverEnvelope) {
        let (seq, tracked) = self.track_outbound_delivery(device_id, envelope);
        self.mark_delivery_sent(device_id, seq);
        (seq, tracked)
    }

    pub fn mark_delivery_sent(&self, device_id: DeviceId, seq: u64) {
        let now = Instant::now();
        let _ = self.with_resume_state_mut(device_id, |entry| entry.mark_sent(seq, now));
    }

    pub async fn ack_by_seq(
        &self,
        device_id: DeviceId,
        seq: u64,
        expected_delivery_id: Option<&str>,
    ) -> Result<Option<String>, crate::Error> {
        let result = self
            .with_resume_state_mut(device_id, |entry| {
                entry.ack_by_seq(seq, expected_delivery_id, Instant::now())
            })
            .flatten();
        if result.is_none() {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "private.resume_ack_by_seq_missed",
                device_id = %(crate::util::redact_text(crate::util::encode_crockford_base32_128(&device_id))),
                seq = (seq)
            );
        }
        Ok(result)
    }

    // Resolve without consuming transport state. A failed durable ACK must not
    // erase the only issued capability before reconnect/retry can use it.
    pub(crate) fn peek_delivery_by_seq(
        &self,
        device_id: DeviceId,
        seq: u64,
        expected_delivery_id: &str,
    ) -> Option<protocol::DeliverEnvelope> {
        self.with_resume_state(device_id, |state| {
            state
                .inflight
                .get(&seq)
                .filter(|item| item.delivery.delivery_id == expected_delivery_id)
                .map(|item| item.delivery.clone())
        })
        .flatten()
    }

    pub(crate) fn forget_delivery_after_commit(&self, device_id: DeviceId, delivery: &str) {
        let _ = self.with_resume_state_mut(device_id, |state| {
            let seq = state
                .inflight
                .iter()
                .find_map(|(seq, item)| (item.delivery.delivery_id == delivery).then_some(*seq));
            if let Some(seq) = seq {
                let _ = state.ack_by_seq(seq, Some(delivery), Instant::now());
            }
            state
                .inflight
                .retain(|_, item| item.delivery.delivery_id != delivery);
        });
    }

    fn snapshot_inflight(&self, device_id: DeviceId) -> Vec<(u64, protocol::DeliverEnvelope)> {
        self.with_resume_state(device_id, ResumeState::inflight_snapshot)
            .unwrap_or_default()
    }

    pub(crate) fn next_retransmit_due_in(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> Option<Duration> {
        self.with_resume_state(device_id, |entry| {
            entry.next_retransmit_due_in(
                Instant::now(),
                ack_timeout,
                self.retransmit_window,
                self.retransmit_max_per_window,
                self.retransmit_max_retries,
            )
        })
        .flatten()
    }

    fn collect_retransmit_due(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> Vec<(u64, protocol::DeliverEnvelope)> {
        let now = Instant::now();
        self.with_resume_state_mut(device_id, |entry| {
            entry.collect_retransmit_due(
                now,
                ack_timeout,
                self.retransmit_window,
                self.retransmit_max_per_window,
                self.retransmit_max_per_tick,
                self.retransmit_max_retries,
            )
        })
        .unwrap_or_default()
    }

    pub(crate) fn take_retransmit_outbound(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> Option<(u64, protocol::DeliverEnvelope)> {
        let due = self.collect_retransmit_due(device_id, ack_timeout);
        let (seq, envelope) = due.into_iter().next()?;
        self.mark_delivery_sent(device_id, seq);
        Some((seq, envelope))
    }

    pub(crate) fn poll_retransmit_outbound(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> RetransmitPollResult {
        let exhausted_count = self.drop_exhausted_inflight(device_id, ack_timeout);
        let outbound = self.take_retransmit_outbound(device_id, ack_timeout);
        RetransmitPollResult {
            exhausted_count,
            outbound,
        }
    }

    pub(crate) fn drop_exhausted_inflight(
        &self,
        device_id: DeviceId,
        ack_timeout: Duration,
    ) -> usize {
        self.with_resume_state_mut(device_id, |entry| {
            entry.drop_exhausted(Instant::now(), ack_timeout, self.retransmit_max_retries)
        })
        .unwrap_or(0)
    }
    fn remove_stale_resume_state(&self, device_id: DeviceId, now: Instant) -> bool {
        if self.is_online(device_id) {
            return false;
        }
        self.resume_state
            .remove_if(&device_id, |_, state| {
                now.saturating_duration_since(state.updated_at) >= self.resume_ttl
            })
            .is_some()
    }

    fn prune_stale_resume_state(&self, now: Instant) {
        let stale: Vec<DeviceId> = self
            .resume_state
            .iter()
            .filter_map(|item| {
                if now.saturating_duration_since(item.value().updated_at) >= self.resume_ttl {
                    Some(*item.key())
                } else {
                    None
                }
            })
            .collect();
        // Drop the iteration's resume guards before consulting presence. ACKs,
        // handshakes and sends may have refreshed a candidate since collection;
        // the conditional removal must recheck its current timestamp atomically.
        let stale_count = stale
            .into_iter()
            .filter(|device_id| self.remove_stale_resume_state(*device_id, now))
            .count();
        if stale_count > 0 {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::INFO,
                event = "private.resume_state_pruned",
                devices = (stale_count as u64)
            );
        }
    }
}
