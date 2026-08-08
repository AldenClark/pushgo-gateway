use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use chrono::{TimeZone, Utc};
use hashbrown::HashMap;
use parking_lot::Mutex;
use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{Duration, Instant},
};
use tracing::Instrument;

use crate::value::DeviceKeyRef;
use crate::{
    runtime_config::{GatewayRuntimeProfile, RuntimeCounterRuntimeTuning, RuntimeTuning},
    storage::{
        AutomationCounts, ChannelRuntimeCounterBucket, DeviceRuntimeCounterBucket,
        GatewayRuntimeCounterBucket, OpsRuntimeCounterBucket, Storage,
    },
};

pub const OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED: &str = "dispatch.provider_send_failed";
pub const OPS_METRIC_HTTP_RESPONSE_5XX: &str = "http.response_5xx";
pub const OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_LOOKUP_FAILED: &str =
    "dispatch.invalid_token_cleanup_lookup_failed";
pub const OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_OUTBOX_CLEAR_FAILED: &str =
    "dispatch.invalid_token_cleanup_outbox_clear_failed";

#[derive(Debug, Clone, Default)]
pub struct DeviceRuntimeCounterDelta {
    pub device_key: String,
    pub messages_received: i64,
    pub messages_acked: i64,
    pub private_connected_count: i64,
    pub private_pull_count: i64,
    pub provider_success_count: i64,
    pub provider_failure_count: i64,
    pub private_outbox_enqueued_count: i64,
}

#[derive(Debug, Clone, Default)]
pub struct DispatchCounterEvent {
    pub channel_id: [u8; 16],
    pub occurred_at: i64,
    pub messages_routed: i64,
    pub deliveries_attempted: i64,
    pub deliveries_acked: i64,
    pub private_enqueued: i64,
    pub provider_attempted: i64,
    pub provider_failed: i64,
    pub provider_success: i64,
    pub private_realtime_delivered: i64,
    pub active_private_sessions_max: i64,
    pub device_deltas: Vec<DeviceRuntimeCounterDelta>,
}

#[derive(Debug, Clone)]
enum RuntimeCounterEvent {
    Dispatch(DispatchCounterEvent),
    DeviceDelta {
        occurred_at: i64,
        device_key: String,
        delta: DeviceRuntimeCounterDelta,
    },
    PrivateAck {
        occurred_at: i64,
        device_key: String,
        channel_id: Option<[u8; 16]>,
        acked_count: i64,
    },
    OpsCounter {
        occurred_at: i64,
        metric_key: String,
        metric_value: i64,
    },
}

pub struct RuntimeCounterCollector {
    tx: Mutex<Option<mpsc::Sender<RuntimeCounterEvent>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeCounterShutdownReport {
    pub joined: usize,
    pub panicked: usize,
    pub aborted: usize,
}

impl RuntimeCounterCollector {
    pub fn spawn(store: Storage) -> Arc<Self> {
        Self::spawn_with_mode(store, true, GatewayRuntimeProfile::Small)
    }

    pub fn spawn_with_mode(
        store: Storage,
        enabled: bool,
        runtime_profile: GatewayRuntimeProfile,
    ) -> Arc<Self> {
        if !enabled {
            return Arc::new(Self {
                tx: Mutex::new(None),
                worker: Mutex::new(None),
            });
        }
        let tuning = RuntimeTuning::for_profile(runtime_profile).runtime_counters;
        let channel_capacity = tuning.channel_capacity;
        let (tx, rx) = mpsc::channel(channel_capacity);
        let worker = tokio::spawn(run_runtime_counter_worker(store, rx, tuning).instrument(
            tracing::info_span!(
                "gateway.runtime_counters.worker",
                runtime_profile = %runtime_profile.as_str()
            ),
        ));
        Arc::new(Self {
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
        })
    }

    #[inline]
    fn try_send(&self, event: RuntimeCounterEvent) {
        let tx = self.tx.lock();
        let Some(tx) = tx.as_ref() else {
            return;
        };
        let event_kind = runtime_counter_event_kind(&event);
        if let Err(err) = tx.try_send(event) {
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::INFO,
                        event = "runtime_counters.event_dropped",
                        reason = %("worker_channel_full"),
                        event_kind = %(event_kind)
                    );
                }
                mpsc::error::TrySendError::Closed(_) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "runtime_counters.event_dropped",
                        reason = %("worker_channel_closed"),
                        event_kind = %(event_kind)
                    );
                }
            }
        }
    }

    pub async fn shutdown_until(&self, deadline: Instant) -> RuntimeCounterShutdownReport {
        // Taking the sole sender closes the channel after every event already
        // accepted by `try_send` has been queued. The worker then drains and
        // performs its final flush before it returns.
        self.tx.lock().take();
        let worker = self.worker.lock().take();
        let Some(mut worker) = worker else {
            return RuntimeCounterShutdownReport::default();
        };

        match tokio::time::timeout_at(deadline, &mut worker).await {
            Ok(Ok(())) => RuntimeCounterShutdownReport {
                joined: 1,
                ..RuntimeCounterShutdownReport::default()
            },
            Ok(Err(join_error)) => {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::ERROR,
                    event = "runtime_counters.worker_join_failed",
                    cancelled = (join_error.is_cancelled()),
                    panicked = (join_error.is_panic())
                );
                RuntimeCounterShutdownReport {
                    panicked: 1,
                    ..RuntimeCounterShutdownReport::default()
                }
            }
            Err(_) => {
                worker.abort();
                let _ = worker.await;
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::ERROR,
                    event = "runtime_counters.worker_aborted",
                    reason = %("shutdown_deadline_exceeded")
                );
                RuntimeCounterShutdownReport {
                    aborted: 1,
                    ..RuntimeCounterShutdownReport::default()
                }
            }
        }
    }

    pub fn record_dispatch(&self, event: DispatchCounterEvent) {
        self.try_send(RuntimeCounterEvent::Dispatch(event));
    }

    pub fn record_private_pull(&self, device_key: &str, occurred_at: i64) {
        let Ok(device_key) = DeviceKeyRef::parse(device_key) else {
            return;
        };
        self.try_send(RuntimeCounterEvent::DeviceDelta {
            occurred_at,
            device_key: device_key.into_owned(),
            delta: DeviceRuntimeCounterDelta {
                private_pull_count: 1,
                ..DeviceRuntimeCounterDelta::default()
            },
        });
    }

    pub fn record_private_ack(&self, device_key: &str, acked_count: usize, occurred_at: i64) {
        let Ok(device_key) = DeviceKeyRef::parse(device_key) else {
            return;
        };
        if acked_count == 0 {
            return;
        }
        self.try_send(RuntimeCounterEvent::PrivateAck {
            occurred_at,
            device_key: device_key.into_owned(),
            channel_id: None,
            acked_count: acked_count as i64,
        });
    }

    pub fn record_private_ack_with_channel(
        &self,
        device_key: String,
        channel_id: Option<[u8; 16]>,
        acked_count: usize,
        occurred_at: i64,
    ) {
        let Ok(device_key) = DeviceKeyRef::parse(&device_key) else {
            return;
        };
        if acked_count == 0 {
            return;
        }
        self.try_send(RuntimeCounterEvent::PrivateAck {
            occurred_at,
            device_key: device_key.into_owned(),
            channel_id,
            acked_count: acked_count as i64,
        });
    }

    pub fn record_private_connected(&self, device_key: String) {
        let Ok(device_key) = DeviceKeyRef::parse(&device_key) else {
            return;
        };
        self.try_send(RuntimeCounterEvent::DeviceDelta {
            occurred_at: Utc::now().timestamp(),
            device_key: device_key.into_owned(),
            delta: DeviceRuntimeCounterDelta {
                private_connected_count: 1,
                ..DeviceRuntimeCounterDelta::default()
            },
        });
    }

    pub fn record_provider_send_result(
        &self,
        channel_id: [u8; 16],
        device_key: &str,
        success: bool,
    ) {
        let Ok(device_key) = DeviceKeyRef::parse(device_key) else {
            return;
        };
        let (provider_success, provider_failed) = if success { (1, 0) } else { (0, 1) };
        self.record_dispatch(DispatchCounterEvent {
            channel_id,
            occurred_at: Utc::now().timestamp_millis(),
            provider_success,
            provider_failed,
            device_deltas: vec![DeviceRuntimeCounterDelta {
                device_key: device_key.into_owned(),
                messages_received: provider_success,
                provider_success_count: provider_success,
                provider_failure_count: provider_failed,
                ..DeviceRuntimeCounterDelta::default()
            }],
            ..DispatchCounterEvent::default()
        });
    }

    pub fn record_ops_counter(&self, metric_key: &str, metric_value: i64, occurred_at: i64) {
        let metric_key = metric_key.trim();
        if metric_key.is_empty() || metric_value == 0 {
            return;
        }
        self.try_send(RuntimeCounterEvent::OpsCounter {
            occurred_at,
            metric_key: metric_key.to_string(),
            metric_value,
        });
    }

    pub fn record_ops_counter_now(&self, metric_key: &str, metric_value: i64) {
        self.record_ops_counter(metric_key, metric_value, Utc::now().timestamp());
    }
}

fn runtime_counter_event_kind(event: &RuntimeCounterEvent) -> &'static str {
    match event {
        RuntimeCounterEvent::Dispatch(_) => "dispatch",
        RuntimeCounterEvent::DeviceDelta { .. } => "device_delta",
        RuntimeCounterEvent::PrivateAck { .. } => "private_ack",
        RuntimeCounterEvent::OpsCounter { .. } => "ops_counter",
    }
}

async fn run_runtime_counter_worker(
    store: Storage,
    mut rx: mpsc::Receiver<RuntimeCounterEvent>,
    tuning: RuntimeCounterRuntimeTuning,
) {
    let flush_event_threshold = tuning.flush_event_threshold;
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "runtime_counters.worker_started",
        flush_interval_secs = (tuning.flush_interval_secs),
        flush_event_threshold = (flush_event_threshold as u64),
        retained_row_limit = (tuning.retained_row_limit as u64),
        sample_gateway_runtime_metrics = (tuning.sample_gateway_runtime_metrics)
    );

    let mut interval = tokio::time::interval(Duration::from_secs(tuning.flush_interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut channel_rows: HashMap<([u8; 16], String), ChannelRuntimeCounterBucket> = HashMap::new();
    let mut device_rows: HashMap<(String, String), DeviceRuntimeCounterBucket> = HashMap::new();
    let mut gateway_rows: HashMap<String, GatewayRuntimeCounterBucket> = HashMap::new();
    let mut ops_rows: HashMap<(String, String), OpsRuntimeCounterBucket> = HashMap::new();
    let mut pending_events = 0usize;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    if tuning.sample_gateway_runtime_metrics {
                        sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                    }
                    flush_runtime_counter_batch(
                        &mut channel_rows,
                        &mut device_rows,
                        &mut gateway_rows,
                        &mut ops_rows,
                    )
                    .await;
                                        ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::INFO,
                        event = "runtime_counters.worker_stopped",
                        reason = %("channel_closed")
                    );
                    break;
                };
                pending_events = pending_events.saturating_add(1);
                aggregate_event(
                    event,
                    &mut channel_rows,
                    &mut device_rows,
                    &mut gateway_rows,
                    &mut ops_rows,
                );
                if pending_events >= flush_event_threshold {
                    if tuning.sample_gateway_runtime_metrics {
                        sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                    }
                    flush_runtime_counter_batch(
                        &mut channel_rows,
                        &mut device_rows,
                        &mut gateway_rows,
                        &mut ops_rows,
                    )
                    .await;
                    pending_events = 0;
                }
            }
            _ = interval.tick() => {
                if tuning.sample_gateway_runtime_metrics {
                    sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                }
                if pending_events > 0 || !gateway_rows.is_empty() || !ops_rows.is_empty() {
                    flush_runtime_counter_batch(
                        &mut channel_rows,
                        &mut device_rows,
                        &mut gateway_rows,
                        &mut ops_rows,
                    )
                    .await;
                    pending_events = 0;
                }
            }
        }
    }
}

fn aggregate_event(
    event: RuntimeCounterEvent,
    channel_rows: &mut HashMap<([u8; 16], String), ChannelRuntimeCounterBucket>,
    device_rows: &mut HashMap<(String, String), DeviceRuntimeCounterBucket>,
    gateway_rows: &mut HashMap<String, GatewayRuntimeCounterBucket>,
    ops_rows: &mut HashMap<(String, String), OpsRuntimeCounterBucket>,
) {
    match event {
        RuntimeCounterEvent::Dispatch(dispatch) => {
            let (bucket_date, bucket_hour) = time_buckets(dispatch.occurred_at);

            merge_channel_daily_delta(
                channel_rows,
                ChannelRuntimeCounterBucket {
                    channel_id: dispatch.channel_id,
                    bucket_date: bucket_date.clone(),
                    messages_routed: dispatch.messages_routed,
                    deliveries_attempted: dispatch.deliveries_attempted,
                    deliveries_acked: dispatch.deliveries_acked,
                    private_enqueued: dispatch.private_enqueued,
                    provider_attempted: dispatch.provider_attempted,
                    provider_failed: dispatch.provider_failed,
                    provider_success: dispatch.provider_success,
                    private_realtime_delivered: dispatch.private_realtime_delivered,
                },
            );

            for device in dispatch.device_deltas {
                merge_device_daily_delta(device_rows, &bucket_date, device);
            }

            merge_gateway_hourly_delta(
                gateway_rows,
                GatewayRuntimeCounterBucket {
                    bucket_hour,
                    messages_routed: dispatch.messages_routed,
                    deliveries_attempted: dispatch.deliveries_attempted,
                    deliveries_acked: dispatch.deliveries_acked,
                    active_private_sessions_max: dispatch.active_private_sessions_max,
                    ..GatewayRuntimeCounterBucket::default()
                },
            );
        }
        RuntimeCounterEvent::DeviceDelta {
            occurred_at,
            device_key,
            mut delta,
        } => {
            delta.device_key = device_key;
            let (bucket_date, _) = time_buckets(occurred_at);
            merge_device_daily_delta(device_rows, &bucket_date, delta);
        }
        RuntimeCounterEvent::PrivateAck {
            occurred_at,
            device_key,
            channel_id,
            acked_count,
        } => {
            let (bucket_date, _) = time_buckets(occurred_at);
            merge_device_daily_delta(
                device_rows,
                &bucket_date,
                DeviceRuntimeCounterDelta {
                    device_key,
                    messages_acked: acked_count,
                    ..DeviceRuntimeCounterDelta::default()
                },
            );
            if let Some(channel_id) = channel_id {
                merge_channel_daily_delta(
                    channel_rows,
                    ChannelRuntimeCounterBucket {
                        channel_id,
                        bucket_date,
                        deliveries_acked: acked_count,
                        ..ChannelRuntimeCounterBucket::default()
                    },
                );
            }
        }
        RuntimeCounterEvent::OpsCounter {
            occurred_at,
            metric_key,
            metric_value,
        } => {
            merge_ops_hourly_delta(ops_rows, occurred_at, metric_key, metric_value);
        }
    }
}

fn merge_device_daily_delta(
    device_rows: &mut HashMap<(String, String), DeviceRuntimeCounterBucket>,
    bucket_date: &str,
    delta: DeviceRuntimeCounterDelta,
) {
    let Ok(device_key) = DeviceKeyRef::parse(&delta.device_key) else {
        return;
    };
    let key = (device_key.as_str().to_string(), bucket_date.to_string());
    let row = device_rows
        .entry(key)
        .or_insert_with(|| DeviceRuntimeCounterBucket {
            device_key: device_key.as_str().to_string(),
            bucket_date: bucket_date.to_string(),
            ..DeviceRuntimeCounterBucket::default()
        });
    row.messages_received += delta.messages_received;
    row.messages_acked += delta.messages_acked;
    row.private_connected_count += delta.private_connected_count;
    row.private_pull_count += delta.private_pull_count;
    row.provider_success_count += delta.provider_success_count;
    row.provider_failure_count += delta.provider_failure_count;
    row.private_outbox_enqueued_count += delta.private_outbox_enqueued_count;
}

fn merge_channel_daily_delta(
    channel_rows: &mut HashMap<([u8; 16], String), ChannelRuntimeCounterBucket>,
    delta: ChannelRuntimeCounterBucket,
) {
    let key = (delta.channel_id, delta.bucket_date.clone());
    let row = channel_rows
        .entry(key)
        .or_insert_with(|| ChannelRuntimeCounterBucket {
            channel_id: delta.channel_id,
            bucket_date: delta.bucket_date.clone(),
            ..ChannelRuntimeCounterBucket::default()
        });
    row.messages_routed += delta.messages_routed;
    row.deliveries_attempted += delta.deliveries_attempted;
    row.deliveries_acked += delta.deliveries_acked;
    row.private_enqueued += delta.private_enqueued;
    row.provider_attempted += delta.provider_attempted;
    row.provider_failed += delta.provider_failed;
    row.provider_success += delta.provider_success;
    row.private_realtime_delivered += delta.private_realtime_delivered;
}

fn merge_gateway_hourly_delta(
    gateway_rows: &mut HashMap<String, GatewayRuntimeCounterBucket>,
    delta: GatewayRuntimeCounterBucket,
) {
    let row = gateway_rows
        .entry(delta.bucket_hour.clone())
        .or_insert_with(|| GatewayRuntimeCounterBucket {
            bucket_hour: delta.bucket_hour.clone(),
            ..GatewayRuntimeCounterBucket::default()
        });
    row.messages_routed += delta.messages_routed;
    row.deliveries_attempted += delta.deliveries_attempted;
    row.deliveries_acked += delta.deliveries_acked;
    row.private_outbox_depth_max = row
        .private_outbox_depth_max
        .max(delta.private_outbox_depth_max);
    row.dedupe_pending_max = row.dedupe_pending_max.max(delta.dedupe_pending_max);
    row.active_private_sessions_max = row
        .active_private_sessions_max
        .max(delta.active_private_sessions_max);
}

async fn sample_gateway_runtime_metrics(
    store: &Storage,
    gateway_rows: &mut HashMap<String, GatewayRuntimeCounterBucket>,
) {
    let outbox_depth = store
        .count_private_outbox_total()
        .await
        .map(|value| value as i64)
        .unwrap_or(0);

    let AutomationCounts {
        delivery_dedupe_pending_count,
        ..
    } = store.automation_counts().await.unwrap_or_default();

    let (_, bucket_hour) = time_buckets(Utc::now().timestamp());
    let row =
        gateway_rows
            .entry(bucket_hour.clone())
            .or_insert_with(|| GatewayRuntimeCounterBucket {
                bucket_hour,
                ..GatewayRuntimeCounterBucket::default()
            });
    row.private_outbox_depth_max = row.private_outbox_depth_max.max(outbox_depth);
    row.dedupe_pending_max = row
        .dedupe_pending_max
        .max(delivery_dedupe_pending_count as i64);
}

async fn flush_runtime_counter_batch(
    channel_rows: &mut HashMap<([u8; 16], String), ChannelRuntimeCounterBucket>,
    device_rows: &mut HashMap<(String, String), DeviceRuntimeCounterBucket>,
    gateway_rows: &mut HashMap<String, GatewayRuntimeCounterBucket>,
    ops_rows: &mut HashMap<(String, String), OpsRuntimeCounterBucket>,
) {
    if channel_rows.is_empty()
        && device_rows.is_empty()
        && gateway_rows.is_empty()
        && ops_rows.is_empty()
    {
        return;
    }

    let channel_count = channel_rows.len();
    let device_count = device_rows.len();
    let gateway_count = gateway_rows.len();
    let ops_count = ops_rows.len();
    channel_rows.clear();
    device_rows.clear();
    gateway_rows.clear();
    ops_rows.clear();

    static STATS_BATCH_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = STATS_BATCH_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if should_emit_runtime_counter_batch_trace(count) {
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::DEBUG,
            event = "runtime_counters.batch_observed",
            count = (count),
            channel_rows = (channel_count as u64),
            device_rows = (device_count as u64),
            gateway_rows = (gateway_count as u64),
            ops_rows = (ops_count as u64)
        );
    }
}

#[inline]
fn should_emit_runtime_counter_batch_trace(count: u64) -> bool {
    count <= 8 || count.is_power_of_two()
}

fn merge_ops_hourly_delta(
    ops_rows: &mut HashMap<(String, String), OpsRuntimeCounterBucket>,
    occurred_at: i64,
    metric_key: String,
    metric_value: i64,
) {
    if metric_value == 0 {
        return;
    }
    let metric_key = metric_key.trim();
    if metric_key.is_empty() {
        return;
    }
    let (_, bucket_hour) = time_buckets(occurred_at);
    merge_ops_hourly_bucket_delta(ops_rows, bucket_hour, metric_key.to_string(), metric_value);
}

fn merge_ops_hourly_bucket_delta(
    ops_rows: &mut HashMap<(String, String), OpsRuntimeCounterBucket>,
    bucket_hour: String,
    metric_key: String,
    metric_value: i64,
) {
    if metric_value == 0 {
        return;
    }
    let metric_key = metric_key.trim();
    if metric_key.is_empty() {
        return;
    }
    let key = (bucket_hour.clone(), metric_key.to_string());
    let row = ops_rows
        .entry(key)
        .or_insert_with(|| OpsRuntimeCounterBucket {
            bucket_hour,
            metric_key: metric_key.to_string(),
            ..OpsRuntimeCounterBucket::default()
        });
    row.metric_value += metric_value;
}

fn time_buckets(ts: i64) -> (String, String) {
    let normalized_seconds = if ts.unsigned_abs() >= 1_000_000_000_000u64 {
        ts / 1000
    } else {
        ts
    };
    let dt = Utc
        .timestamp_opt(normalized_seconds, 0)
        .single()
        .unwrap_or_else(Utc::now);
    (
        dt.format("%Y-%m-%d").to_string(),
        dt.format("%Y-%m-%dT%H").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ack_updates_device_and_channel_daily_counters() {
        let mut channel_rows: HashMap<([u8; 16], String), ChannelRuntimeCounterBucket> =
            HashMap::new();
        let mut device_rows: HashMap<(String, String), DeviceRuntimeCounterBucket> = HashMap::new();
        let mut gateway_rows: HashMap<String, GatewayRuntimeCounterBucket> = HashMap::new();
        let mut ops_rows: HashMap<(String, String), OpsRuntimeCounterBucket> = HashMap::new();
        let channel_id = [7u8; 16];
        let occurred_at = 1_711_000_000;

        aggregate_event(
            RuntimeCounterEvent::PrivateAck {
                occurred_at,
                device_key: "private:abc".to_string(),
                channel_id: Some(channel_id),
                acked_count: 2,
            },
            &mut channel_rows,
            &mut device_rows,
            &mut gateway_rows,
            &mut ops_rows,
        );

        let (bucket_date, _) = time_buckets(occurred_at);
        let channel = channel_rows
            .get(&(channel_id, bucket_date.clone()))
            .expect("channel row should exist");
        assert_eq!(channel.deliveries_acked, 2);

        let device = device_rows
            .get(&("private:abc".to_string(), bucket_date))
            .expect("device row should exist");
        assert_eq!(device.messages_acked, 2);
    }

    #[test]
    fn dispatch_event_accumulates_provider_counters() {
        let mut channel_rows: HashMap<([u8; 16], String), ChannelRuntimeCounterBucket> =
            HashMap::new();
        let mut device_rows: HashMap<(String, String), DeviceRuntimeCounterBucket> = HashMap::new();
        let mut gateway_rows: HashMap<String, GatewayRuntimeCounterBucket> = HashMap::new();
        let mut ops_rows: HashMap<(String, String), OpsRuntimeCounterBucket> = HashMap::new();
        let channel_id = [1u8; 16];
        let occurred_at = 1_711_000_100;

        aggregate_event(
            RuntimeCounterEvent::Dispatch(DispatchCounterEvent {
                channel_id,
                occurred_at,
                messages_routed: 1,
                deliveries_attempted: 3,
                deliveries_acked: 0,
                private_enqueued: 1,
                provider_attempted: 2,
                provider_failed: 1,
                provider_success: 1,
                private_realtime_delivered: 1,
                active_private_sessions_max: 9,
                device_deltas: vec![DeviceRuntimeCounterDelta {
                    device_key: "provider:android:a".to_string(),
                    messages_received: 1,
                    provider_success_count: 1,
                    ..DeviceRuntimeCounterDelta::default()
                }],
            }),
            &mut channel_rows,
            &mut device_rows,
            &mut gateway_rows,
            &mut ops_rows,
        );

        let (bucket_date, bucket_hour) = time_buckets(occurred_at);
        let channel = channel_rows
            .get(&(channel_id, bucket_date))
            .expect("channel row should exist");
        assert_eq!(channel.provider_attempted, 2);
        assert_eq!(channel.provider_failed, 1);
        assert_eq!(channel.provider_success, 1);

        let gateway = gateway_rows
            .get(&bucket_hour)
            .expect("gateway row should exist");
        assert_eq!(gateway.deliveries_attempted, 3);
        assert_eq!(gateway.active_private_sessions_max, 9);
    }

    #[test]
    fn ops_counter_accumulates_by_hour_and_metric() {
        let mut channel_rows: HashMap<([u8; 16], String), ChannelRuntimeCounterBucket> =
            HashMap::new();
        let mut device_rows: HashMap<(String, String), DeviceRuntimeCounterBucket> = HashMap::new();
        let mut gateway_rows: HashMap<String, GatewayRuntimeCounterBucket> = HashMap::new();
        let mut ops_rows: HashMap<(String, String), OpsRuntimeCounterBucket> = HashMap::new();
        let occurred_at = 1_711_000_100;
        let (_, bucket_hour) = time_buckets(occurred_at);

        aggregate_event(
            RuntimeCounterEvent::OpsCounter {
                occurred_at,
                metric_key: "dispatch.provider_send_failed".to_string(),
                metric_value: 1,
            },
            &mut channel_rows,
            &mut device_rows,
            &mut gateway_rows,
            &mut ops_rows,
        );
        aggregate_event(
            RuntimeCounterEvent::OpsCounter {
                occurred_at,
                metric_key: "dispatch.provider_send_failed".to_string(),
                metric_value: 2,
            },
            &mut channel_rows,
            &mut device_rows,
            &mut gateway_rows,
            &mut ops_rows,
        );

        let key = (bucket_hour, "dispatch.provider_send_failed".to_string());
        let row = ops_rows.get(&key).expect("ops row should exist");
        assert_eq!(row.metric_value, 3);
    }
}
