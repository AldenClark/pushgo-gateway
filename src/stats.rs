use std::sync::Arc;

use chrono::{TimeZone, Utc};
use hashbrown::HashMap;
use tokio::{sync::mpsc, time::Duration};

use crate::storage::{
    AutomationCounts, ChannelStatsDailyDelta, DeviceStatsDailyDelta, GatewayStatsHourlyDelta,
    OpsStatsHourlyDelta, StatsBatchWrite, Storage,
};
use crate::util::TraceEvent;

const STATS_FLUSH_INTERVAL_SECS: u64 = 2;
const STATS_FLUSH_EVENT_THRESHOLD: usize = 1024;

pub const OPS_METRIC_DISPATCH_PROVIDER_SEND_FAILED: &str = "dispatch.provider_send_failed";
pub const OPS_METRIC_HTTP_RESPONSE_5XX: &str = "http.response_5xx";
pub const OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_LOOKUP_FAILED: &str =
    "dispatch.invalid_token_cleanup_lookup_failed";
pub const OPS_METRIC_DISPATCH_INVALID_TOKEN_CLEANUP_OUTBOX_CLEAR_FAILED: &str =
    "dispatch.invalid_token_cleanup_outbox_clear_failed";

#[derive(Debug, Clone, Default)]
pub struct DeviceDispatchDelta {
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
pub struct DispatchStatsEvent {
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
    pub device_deltas: Vec<DeviceDispatchDelta>,
}

#[derive(Debug, Clone)]
enum StatsEvent {
    Dispatch(DispatchStatsEvent),
    DeviceDelta {
        occurred_at: i64,
        device_key: String,
        delta: DeviceDispatchDelta,
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

#[derive(Clone)]
pub struct StatsCollector {
    tx: Option<mpsc::UnboundedSender<StatsEvent>>,
}

impl StatsCollector {
    pub fn spawn(store: Storage) -> Arc<Self> {
        Self::spawn_with_mode(store, true)
    }

    pub fn spawn_with_mode(store: Storage, enabled: bool) -> Arc<Self> {
        if !enabled {
            return Arc::new(Self { tx: None });
        }
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(run_stats_worker(store, rx));
        Arc::new(Self { tx: Some(tx) })
    }

    #[inline]
    fn try_send(&self, event: StatsEvent) {
        let Some(tx) = &self.tx else {
            return;
        };
        let _ = tx.send(event);
    }

    pub fn record_dispatch(&self, event: DispatchStatsEvent) {
        self.try_send(StatsEvent::Dispatch(event));
    }

    pub fn record_private_pull(&self, device_key: &str, occurred_at: i64) {
        let device_key = device_key.trim();
        if device_key.is_empty() {
            return;
        }
        self.try_send(StatsEvent::DeviceDelta {
            occurred_at,
            device_key: device_key.to_string(),
            delta: DeviceDispatchDelta {
                private_pull_count: 1,
                ..DeviceDispatchDelta::default()
            },
        });
    }

    pub fn record_private_ack(&self, device_key: &str, acked_count: usize, occurred_at: i64) {
        let device_key = device_key.trim();
        if device_key.is_empty() || acked_count == 0 {
            return;
        }
        self.try_send(StatsEvent::PrivateAck {
            occurred_at,
            device_key: device_key.to_string(),
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
        if device_key.trim().is_empty() || acked_count == 0 {
            return;
        }
        self.try_send(StatsEvent::PrivateAck {
            occurred_at,
            device_key,
            channel_id,
            acked_count: acked_count as i64,
        });
    }

    pub fn record_private_connected(&self, device_key: String) {
        if device_key.trim().is_empty() {
            return;
        }
        self.try_send(StatsEvent::DeviceDelta {
            occurred_at: Utc::now().timestamp(),
            device_key,
            delta: DeviceDispatchDelta {
                private_connected_count: 1,
                ..DeviceDispatchDelta::default()
            },
        });
    }

    pub fn record_ops_counter(&self, metric_key: &str, metric_value: i64, occurred_at: i64) {
        let metric_key = metric_key.trim();
        if metric_key.is_empty() || metric_value == 0 {
            return;
        }
        self.try_send(StatsEvent::OpsCounter {
            occurred_at,
            metric_key: metric_key.to_string(),
            metric_value,
        });
    }

    pub fn record_ops_counter_now(&self, metric_key: &str, metric_value: i64) {
        self.record_ops_counter(metric_key, metric_value, Utc::now().timestamp());
    }
}

async fn run_stats_worker(store: Storage, mut rx: mpsc::UnboundedReceiver<StatsEvent>) {
    let mut interval = tokio::time::interval(Duration::from_secs(STATS_FLUSH_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut channel_rows: HashMap<([u8; 16], String), ChannelStatsDailyDelta> = HashMap::new();
    let mut device_rows: HashMap<(String, String), DeviceStatsDailyDelta> = HashMap::new();
    let mut gateway_rows: HashMap<String, GatewayStatsHourlyDelta> = HashMap::new();
    let mut ops_rows: HashMap<(String, String), OpsStatsHourlyDelta> = HashMap::new();
    let mut pending_events = 0usize;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                    flush_stats_batch(
                        &store,
                        &mut channel_rows,
                        &mut device_rows,
                        &mut gateway_rows,
                        &mut ops_rows,
                    )
                    .await;
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
                if pending_events >= STATS_FLUSH_EVENT_THRESHOLD {
                    sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                    flush_stats_batch(
                        &store,
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
                sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                if pending_events > 0 || !gateway_rows.is_empty() || !ops_rows.is_empty() {
                    flush_stats_batch(
                        &store,
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
    event: StatsEvent,
    channel_rows: &mut HashMap<([u8; 16], String), ChannelStatsDailyDelta>,
    device_rows: &mut HashMap<(String, String), DeviceStatsDailyDelta>,
    gateway_rows: &mut HashMap<String, GatewayStatsHourlyDelta>,
    ops_rows: &mut HashMap<(String, String), OpsStatsHourlyDelta>,
) {
    match event {
        StatsEvent::Dispatch(dispatch) => {
            let (bucket_date, bucket_hour) = time_buckets(dispatch.occurred_at);

            merge_channel_daily_delta(
                channel_rows,
                ChannelStatsDailyDelta {
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
                GatewayStatsHourlyDelta {
                    bucket_hour,
                    messages_routed: dispatch.messages_routed,
                    deliveries_attempted: dispatch.deliveries_attempted,
                    deliveries_acked: dispatch.deliveries_acked,
                    active_private_sessions_max: dispatch.active_private_sessions_max,
                    ..GatewayStatsHourlyDelta::default()
                },
            );
        }
        StatsEvent::DeviceDelta {
            occurred_at,
            device_key,
            mut delta,
        } => {
            delta.device_key = device_key;
            let (bucket_date, _) = time_buckets(occurred_at);
            merge_device_daily_delta(device_rows, &bucket_date, delta);
        }
        StatsEvent::PrivateAck {
            occurred_at,
            device_key,
            channel_id,
            acked_count,
        } => {
            let (bucket_date, _) = time_buckets(occurred_at);
            merge_device_daily_delta(
                device_rows,
                &bucket_date,
                DeviceDispatchDelta {
                    device_key,
                    messages_acked: acked_count,
                    ..DeviceDispatchDelta::default()
                },
            );
            if let Some(channel_id) = channel_id {
                merge_channel_daily_delta(
                    channel_rows,
                    ChannelStatsDailyDelta {
                        channel_id,
                        bucket_date,
                        deliveries_acked: acked_count,
                        ..ChannelStatsDailyDelta::default()
                    },
                );
            }
        }
        StatsEvent::OpsCounter {
            occurred_at,
            metric_key,
            metric_value,
        } => {
            merge_ops_hourly_delta(ops_rows, occurred_at, metric_key, metric_value);
        }
    }
}

fn merge_device_daily_delta(
    device_rows: &mut HashMap<(String, String), DeviceStatsDailyDelta>,
    bucket_date: &str,
    delta: DeviceDispatchDelta,
) {
    let device_key_trimmed = delta.device_key.trim();
    if device_key_trimmed.is_empty() {
        return;
    }
    let key = (device_key_trimmed.to_string(), bucket_date.to_string());
    let row = device_rows
        .entry(key)
        .or_insert_with(|| DeviceStatsDailyDelta {
            device_key: device_key_trimmed.to_string(),
            bucket_date: bucket_date.to_string(),
            ..DeviceStatsDailyDelta::default()
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
    channel_rows: &mut HashMap<([u8; 16], String), ChannelStatsDailyDelta>,
    delta: ChannelStatsDailyDelta,
) {
    let key = (delta.channel_id, delta.bucket_date.clone());
    let row = channel_rows
        .entry(key)
        .or_insert_with(|| ChannelStatsDailyDelta {
            channel_id: delta.channel_id,
            bucket_date: delta.bucket_date.clone(),
            ..ChannelStatsDailyDelta::default()
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
    gateway_rows: &mut HashMap<String, GatewayStatsHourlyDelta>,
    delta: GatewayStatsHourlyDelta,
) {
    let row = gateway_rows
        .entry(delta.bucket_hour.clone())
        .or_insert_with(|| GatewayStatsHourlyDelta {
            bucket_hour: delta.bucket_hour.clone(),
            ..GatewayStatsHourlyDelta::default()
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
    gateway_rows: &mut HashMap<String, GatewayStatsHourlyDelta>,
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
    let row = gateway_rows
        .entry(bucket_hour.clone())
        .or_insert_with(|| GatewayStatsHourlyDelta {
            bucket_hour,
            ..GatewayStatsHourlyDelta::default()
        });
    row.private_outbox_depth_max = row.private_outbox_depth_max.max(outbox_depth);
    row.dedupe_pending_max = row
        .dedupe_pending_max
        .max(delivery_dedupe_pending_count as i64);
}

async fn flush_stats_batch(
    store: &Storage,
    channel_rows: &mut HashMap<([u8; 16], String), ChannelStatsDailyDelta>,
    device_rows: &mut HashMap<(String, String), DeviceStatsDailyDelta>,
    gateway_rows: &mut HashMap<String, GatewayStatsHourlyDelta>,
    ops_rows: &mut HashMap<(String, String), OpsStatsHourlyDelta>,
) {
    if channel_rows.is_empty()
        && device_rows.is_empty()
        && gateway_rows.is_empty()
        && ops_rows.is_empty()
    {
        return;
    }

    let mut batch = StatsBatchWrite::default();
    let channel_count = channel_rows.len();
    let device_count = device_rows.len();
    let gateway_count = gateway_rows.len();
    let ops_count = ops_rows.len();
    batch
        .channels
        .extend(channel_rows.drain().map(|(_, row)| row));
    batch
        .devices
        .extend(device_rows.drain().map(|(_, row)| row));
    batch
        .gateway
        .extend(gateway_rows.drain().map(|(_, row)| row));
    batch.ops.extend(ops_rows.drain().map(|(_, row)| row));

    if let Err(err) = store.apply_stats_batch(&batch).await {
        restore_failed_stats_batch(&batch, channel_rows, device_rows, gateway_rows, ops_rows);
        TraceEvent::new("stats.batch_write_failed")
            .field_u64("channel_rows", channel_count as u64)
            .field_u64("device_rows", device_count as u64)
            .field_u64("gateway_rows", gateway_count as u64)
            .field_u64("ops_rows", ops_count as u64)
            .field_str("error", err.to_string())
            .emit();
    }
}

fn restore_failed_stats_batch(
    batch: &StatsBatchWrite,
    channel_rows: &mut HashMap<([u8; 16], String), ChannelStatsDailyDelta>,
    device_rows: &mut HashMap<(String, String), DeviceStatsDailyDelta>,
    gateway_rows: &mut HashMap<String, GatewayStatsHourlyDelta>,
    ops_rows: &mut HashMap<(String, String), OpsStatsHourlyDelta>,
) {
    for row in &batch.channels {
        merge_channel_daily_delta(channel_rows, row.clone());
    }
    for row in &batch.devices {
        merge_device_daily_delta(
            device_rows,
            row.bucket_date.as_str(),
            DeviceDispatchDelta {
                device_key: row.device_key.clone(),
                messages_received: row.messages_received,
                messages_acked: row.messages_acked,
                private_connected_count: row.private_connected_count,
                private_pull_count: row.private_pull_count,
                provider_success_count: row.provider_success_count,
                provider_failure_count: row.provider_failure_count,
                private_outbox_enqueued_count: row.private_outbox_enqueued_count,
            },
        );
    }
    for row in &batch.gateway {
        merge_gateway_hourly_delta(gateway_rows, row.clone());
    }
    for row in &batch.ops {
        merge_ops_hourly_bucket_delta(
            ops_rows,
            row.bucket_hour.clone(),
            row.metric_key.clone(),
            row.metric_value,
        );
    }
}

fn merge_ops_hourly_delta(
    ops_rows: &mut HashMap<(String, String), OpsStatsHourlyDelta>,
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
    ops_rows: &mut HashMap<(String, String), OpsStatsHourlyDelta>,
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
    let row = ops_rows.entry(key).or_insert_with(|| OpsStatsHourlyDelta {
        bucket_hour,
        metric_key: metric_key.to_string(),
        ..OpsStatsHourlyDelta::default()
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
        let mut channel_rows: HashMap<([u8; 16], String), ChannelStatsDailyDelta> = HashMap::new();
        let mut device_rows: HashMap<(String, String), DeviceStatsDailyDelta> = HashMap::new();
        let mut gateway_rows: HashMap<String, GatewayStatsHourlyDelta> = HashMap::new();
        let mut ops_rows: HashMap<(String, String), OpsStatsHourlyDelta> = HashMap::new();
        let channel_id = [7u8; 16];
        let occurred_at = 1_711_000_000;

        aggregate_event(
            StatsEvent::PrivateAck {
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
        let mut channel_rows: HashMap<([u8; 16], String), ChannelStatsDailyDelta> = HashMap::new();
        let mut device_rows: HashMap<(String, String), DeviceStatsDailyDelta> = HashMap::new();
        let mut gateway_rows: HashMap<String, GatewayStatsHourlyDelta> = HashMap::new();
        let mut ops_rows: HashMap<(String, String), OpsStatsHourlyDelta> = HashMap::new();
        let channel_id = [1u8; 16];
        let occurred_at = 1_711_000_100;

        aggregate_event(
            StatsEvent::Dispatch(DispatchStatsEvent {
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
                device_deltas: vec![DeviceDispatchDelta {
                    device_key: "provider:android:a".to_string(),
                    messages_received: 1,
                    provider_success_count: 1,
                    ..DeviceDispatchDelta::default()
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
        let mut channel_rows: HashMap<([u8; 16], String), ChannelStatsDailyDelta> = HashMap::new();
        let mut device_rows: HashMap<(String, String), DeviceStatsDailyDelta> = HashMap::new();
        let mut gateway_rows: HashMap<String, GatewayStatsHourlyDelta> = HashMap::new();
        let mut ops_rows: HashMap<(String, String), OpsStatsHourlyDelta> = HashMap::new();
        let occurred_at = 1_711_000_100;
        let (_, bucket_hour) = time_buckets(occurred_at);

        aggregate_event(
            StatsEvent::OpsCounter {
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
            StatsEvent::OpsCounter {
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
