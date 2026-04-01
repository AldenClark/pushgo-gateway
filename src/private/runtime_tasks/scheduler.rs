use super::*;

#[derive(Default)]
pub(super) struct FallbackScheduler {
    heap: BinaryHeap<FallbackTaskEntry>,
    active: HashMap<SchedulerTaskKey, (i64, u64)>,
    fallback_depth: usize,
    next_sequence: u64,
}

impl FallbackScheduler {
    pub(super) fn apply(&mut self, cmd: FallbackTaskCommand) {
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

    pub(super) fn schedule(&mut self, key: FallbackTaskKey, due_at_unix_secs: i64) {
        self.schedule_task(SchedulerTaskKey::Fallback(key), due_at_unix_secs);
    }

    pub(super) fn schedule_maintenance(&mut self, due_at_unix_secs: i64) {
        self.schedule_task(SchedulerTaskKey::Maintenance, due_at_unix_secs);
    }

    pub(super) fn replace_fallback_tasks<I>(&mut self, entries: I)
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

    pub(super) fn merge_fallback_tasks<I>(&mut self, entries: I)
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

    pub(super) fn next_due_unix_secs(&mut self) -> Option<i64> {
        self.prune_stale();
        self.heap.peek().map(|entry| entry.due_at_unix_secs)
    }

    pub(super) fn pop_due(&mut self, now: i64, max_batch: usize) -> Vec<(SchedulerTaskKey, i64)> {
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

    pub(super) fn depth(&self) -> usize {
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
