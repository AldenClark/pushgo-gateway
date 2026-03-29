use std::sync::Arc;

use chrono::{TimeZone, Utc};
use hashbrown::HashMap;
use tokio::{sync::mpsc, time::Duration};

use crate::storage::{
    AutomationCounts, ChannelStatsDailyDelta, DeviceStatsDailyDelta, GatewayStatsHourlyDelta,
    StatsBatchWrite, Storage,
};

const STATS_EVENT_CHANNEL_CAPACITY: usize = 8192;
const STATS_FLUSH_INTERVAL_SECS: u64 = 2;
const STATS_FLUSH_EVENT_THRESHOLD: usize = 1024;

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
}

#[derive(Clone)]
pub struct StatsCollector {
    tx: mpsc::Sender<StatsEvent>,
}

impl StatsCollector {
    pub fn spawn(store: Storage) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(STATS_EVENT_CHANNEL_CAPACITY);
        tokio::spawn(run_stats_worker(store, rx));
        Arc::new(Self { tx })
    }

    pub fn record_dispatch(&self, event: DispatchStatsEvent) {
        let _ = self.tx.try_send(StatsEvent::Dispatch(event));
    }

    pub fn record_private_pull(&self, device_key: &str, occurred_at: i64) {
        let device_key = device_key.trim();
        if device_key.is_empty() {
            return;
        }
        let _ = self.tx.try_send(StatsEvent::DeviceDelta {
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
        let _ = self.tx.try_send(StatsEvent::PrivateAck {
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
        let _ = self.tx.try_send(StatsEvent::PrivateAck {
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
        let _ = self.tx.try_send(StatsEvent::DeviceDelta {
            occurred_at: Utc::now().timestamp(),
            device_key,
            delta: DeviceDispatchDelta {
                private_connected_count: 1,
                ..DeviceDispatchDelta::default()
            },
        });
    }
}

async fn run_stats_worker(store: Storage, mut rx: mpsc::Receiver<StatsEvent>) {
    let mut interval = tokio::time::interval(Duration::from_secs(STATS_FLUSH_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut channel_rows: HashMap<([u8; 16], String), ChannelStatsDailyDelta> = HashMap::new();
    let mut device_rows: HashMap<(String, String), DeviceStatsDailyDelta> = HashMap::new();
    let mut gateway_rows: HashMap<String, GatewayStatsHourlyDelta> = HashMap::new();
    let mut pending_events = 0usize;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else {
                    sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                    flush_stats_batch(&store, &mut channel_rows, &mut device_rows, &mut gateway_rows).await;
                    break;
                };
                pending_events = pending_events.saturating_add(1);
                aggregate_event(event, &mut channel_rows, &mut device_rows, &mut gateway_rows);
                if pending_events >= STATS_FLUSH_EVENT_THRESHOLD {
                    sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                    flush_stats_batch(&store, &mut channel_rows, &mut device_rows, &mut gateway_rows).await;
                    pending_events = 0;
                }
            }
            _ = interval.tick() => {
                sample_gateway_runtime_metrics(&store, &mut gateway_rows).await;
                if pending_events > 0 || !gateway_rows.is_empty() {
                    flush_stats_batch(&store, &mut channel_rows, &mut device_rows, &mut gateway_rows).await;
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
) {
    match event {
        StatsEvent::Dispatch(dispatch) => {
            let (bucket_date, bucket_hour) = time_buckets(dispatch.occurred_at);

            let channel_key = (dispatch.channel_id, bucket_date.clone());
            let channel_row =
                channel_rows
                    .entry(channel_key)
                    .or_insert_with(|| ChannelStatsDailyDelta {
                        channel_id: dispatch.channel_id,
                        bucket_date: bucket_date.clone(),
                        ..ChannelStatsDailyDelta::default()
                    });
            channel_row.messages_routed += dispatch.messages_routed;
            channel_row.deliveries_attempted += dispatch.deliveries_attempted;
            channel_row.deliveries_acked += dispatch.deliveries_acked;
            channel_row.private_enqueued += dispatch.private_enqueued;
            channel_row.provider_attempted += dispatch.provider_attempted;
            channel_row.provider_failed += dispatch.provider_failed;
            channel_row.provider_success += dispatch.provider_success;
            channel_row.private_realtime_delivered += dispatch.private_realtime_delivered;

            for device in dispatch.device_deltas {
                merge_device_daily_delta(device_rows, &bucket_date, device);
            }

            let gateway_row = gateway_rows.entry(bucket_hour.clone()).or_insert_with(|| {
                GatewayStatsHourlyDelta {
                    bucket_hour,
                    ..GatewayStatsHourlyDelta::default()
                }
            });
            gateway_row.messages_routed += dispatch.messages_routed;
            gateway_row.deliveries_attempted += dispatch.deliveries_attempted;
            gateway_row.deliveries_acked += dispatch.deliveries_acked;
            gateway_row.active_private_sessions_max = gateway_row
                .active_private_sessions_max
                .max(dispatch.active_private_sessions_max);
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
                let channel_key = (channel_id, bucket_date.clone());
                let channel_row =
                    channel_rows
                        .entry(channel_key)
                        .or_insert_with(|| ChannelStatsDailyDelta {
                            channel_id,
                            bucket_date: bucket_date.clone(),
                            ..ChannelStatsDailyDelta::default()
                        });
                channel_row.deliveries_acked += acked_count;
            }
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
) {
    if channel_rows.is_empty() && device_rows.is_empty() && gateway_rows.is_empty() {
        return;
    }

    let mut batch = StatsBatchWrite::default();
    batch
        .channels
        .extend(channel_rows.drain().map(|(_, row)| row));
    batch
        .devices
        .extend(device_rows.drain().map(|(_, row)| row));
    batch
        .gateway
        .extend(gateway_rows.drain().map(|(_, row)| row));

    let _ = store.apply_stats_batch(&batch).await;
}

fn time_buckets(ts: i64) -> (String, String) {
    let dt = Utc.timestamp_opt(ts, 0).single().unwrap_or_else(Utc::now);
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
}
