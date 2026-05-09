impl PrivateHub {
    pub(crate) fn memory_snapshot(&self) -> PrivateHubMemorySnapshot {
        let mut hot_messages_payload_bytes = 0usize;
        self.hot_messages.iter().for_each(|entry| {
            hot_messages_payload_bytes =
                hot_messages_payload_bytes.saturating_add(entry.value().payload.len());
        });

        let (hot_order_len, hot_order_capacity) = {
            let order = self.hot_order.lock();
            (order.len(), order.capacity())
        };

        let mut resume_inflight_count = 0usize;
        let mut resume_inflight_payload_bytes = 0usize;
        self.resume_state.iter().for_each(|entry| {
            let state = entry.value();
            resume_inflight_count = resume_inflight_count.saturating_add(state.inflight.len());
            for inflight in state.inflight.values() {
                resume_inflight_payload_bytes =
                    resume_inflight_payload_bytes.saturating_add(inflight.delivery.payload.len());
            }
        });

        let mut presence_active_conn_count = 0usize;
        let mut presence_draining_conn_count = 0usize;
        let mut presence_queue_depth = 0usize;
        let mut presence_queue_capacity = 0usize;
        self.presence.iter().for_each(|entry| {
            let presence = entry.value();
            let mut push_sender = |sender: &Sender<protocol::DeliverEnvelope>| {
                presence_queue_depth = presence_queue_depth.saturating_add(sender.len());
                presence_queue_capacity = presence_queue_capacity
                    .saturating_add(sender.capacity().unwrap_or(0));
            };
            if let Some(active) = presence.quic_active.as_ref() {
                presence_active_conn_count = presence_active_conn_count.saturating_add(1);
                push_sender(&active.sender);
            }
            if let Some(active) = presence.tcp_active.as_ref() {
                presence_active_conn_count = presence_active_conn_count.saturating_add(1);
                push_sender(&active.sender);
            }
            if let Some(active) = presence.wss_active.as_ref() {
                presence_active_conn_count = presence_active_conn_count.saturating_add(1);
                push_sender(&active.sender);
            }
            presence_draining_conn_count =
                presence_draining_conn_count.saturating_add(presence.draining.len());
            for draining in &presence.draining {
                push_sender(&draining.sender);
            }
        });

        PrivateHubMemorySnapshot {
            hot_messages_count: self.hot_messages.len(),
            hot_messages_payload_bytes,
            hot_order_len,
            hot_order_capacity,
            resume_state_count: self.resume_state.len(),
            resume_inflight_count,
            resume_inflight_payload_bytes,
            presence_device_count: self.presence.len(),
            presence_active_conn_count,
            presence_draining_conn_count,
            presence_queue_depth,
            presence_queue_capacity,
        }
    }
}
