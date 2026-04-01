impl PrivateHub {
    pub fn hot_cache_target_for_pending(&self, pending_outbox: usize) -> usize {
        let floor = self.hot_cache_capacity.clamp(1, 256);
        pending_outbox
            .saturating_mul(2)
            .clamp(floor, self.hot_cache_capacity)
    }

    pub fn compact_hot_cache(&self, target_capacity: usize) {
        let target_capacity = target_capacity.clamp(1, self.hot_cache_capacity);
        let retained_ids = {
            let mut order = self.hot_order.lock();
            if order.len() > 1 {
                let mut seen = HashSet::with_capacity(order.len());
                let mut deduped = VecDeque::with_capacity(order.len());
                for delivery_id in order.iter().rev() {
                    if seen.insert(delivery_id.clone()) {
                        deduped.push_front(delivery_id.clone());
                    }
                }
                *order = deduped;
            }
            self.trim_hot_cache_locked(&mut order, target_capacity);
            let shrink_threshold = target_capacity.saturating_mul(4).max(1024);
            if order.capacity() > shrink_threshold {
                order.shrink_to_fit();
            }
            order.iter().cloned().collect::<HashSet<String>>()
        };

        if self.hot_messages.len() <= retained_ids.len() {
            return;
        }
        let stale_keys: Vec<String> = self
            .hot_messages
            .iter()
            .filter_map(|entry| {
                (!retained_ids.contains(entry.key().as_str())).then(|| entry.key().clone())
            })
            .collect();
        for key in stale_keys {
            self.hot_messages.remove(key.as_str());
        }
    }

    fn cache_put(&self, delivery_id: &str, message: &PrivateMessage) {
        let inserted = self
            .hot_messages
            .insert(delivery_id.to_string(), message.clone())
            .is_none();
        if !inserted {
            return;
        }
        let mut order = self.hot_order.lock();
        order.push_back(delivery_id.to_string());
        self.trim_hot_cache_locked(&mut order, self.hot_cache_capacity);
    }

    fn trim_hot_cache_locked(&self, order: &mut VecDeque<String>, target_capacity: usize) {
        while order.len() > target_capacity {
            if let Some(stale) = order.pop_front() {
                self.hot_messages.remove(stale.as_str());
            }
        }
    }
}
