impl PrivateHub {
    fn ensure_resume_state_mut<R>(
        &self,
        device_id: DeviceId,
        now: Instant,
        f: impl FnOnce(&mut ResumeState) -> R,
    ) -> R {
        let mut entry = self
            .resume_state
            .entry(device_id)
            .or_insert_with(|| ResumeState::fresh(now));
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
        self.prune_stale_resume_state(now);
        let incoming = client_resume_token
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or_default();
        let (resume_token, acked_delivery_ids) =
            self.ensure_resume_state_mut(device_id, now, |entry| {
                let token_mismatch = incoming.is_empty() || incoming != entry.token;
                let ack_watermark_out_of_range =
                    !token_mismatch && last_acked_seq > entry.next_seq.saturating_sub(1);
                if token_mismatch || ack_watermark_out_of_range {
                    entry.reset(now);
                }
                let acked_delivery_ids = entry.ack_up_to(last_acked_seq, now);
                (entry.token.clone(), acked_delivery_ids)
            });

        ResumeHandshake {
            resume_token,
            acked_delivery_ids,
        }
    }

    pub fn track_outbound_delivery(
        &self,
        device_id: DeviceId,
        envelope: protocol::DeliverEnvelope,
    ) -> (u64, protocol::DeliverEnvelope) {
        let now = Instant::now();
        self.prune_stale_resume_state(now);
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
        Ok(self
            .with_resume_state_mut(device_id, |entry| {
                entry.ack_by_seq(seq, expected_delivery_id, Instant::now())
            })
            .flatten())
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
    fn prune_stale_resume_state(&self, now: Instant) {
        if self.resume_state.len() < 128 {
            return;
        }
        let stale: Vec<DeviceId> = self
            .resume_state
            .iter()
            .filter_map(|item| {
                if now.duration_since(item.value().updated_at) >= self.resume_ttl
                    && !self.is_online(*item.key())
                {
                    Some(*item.key())
                } else {
                    None
                }
            })
            .collect();
        for device_id in stale {
            self.resume_state.remove(&device_id);
        }
    }
}
