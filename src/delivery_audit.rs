use std::sync::Arc;

use tokio::{
    sync::mpsc,
    time::{self, Duration},
};

use crate::{
    dispatch::audit::{DispatchAuditLog, DispatchAuditRecord},
    storage::{DeliveryAuditWrite, Store},
};

const DEFAULT_DELIVERY_AUDIT_CHANNEL_CAPACITY: usize = 16_384;
const DEFAULT_DELIVERY_AUDIT_BATCH_SIZE: usize = 256;
const DEFAULT_DELIVERY_AUDIT_FLUSH_INTERVAL_MS: u64 = 50;

#[derive(Debug)]
struct DeliveryAuditQueued {
    correlation_id: String,
    entry: DeliveryAuditWrite,
}

#[derive(Clone)]
pub(crate) struct DeliveryAuditCollector {
    enabled: bool,
    tx: Option<mpsc::Sender<DeliveryAuditQueued>>,
}

impl DeliveryAuditCollector {
    pub(crate) fn spawn(enabled: bool, store: Store, audit: Arc<DispatchAuditLog>) -> Arc<Self> {
        if !enabled {
            return Arc::new(Self {
                enabled: false,
                tx: None,
            });
        }

        let channel_capacity = parse_env_usize(
            "PUSHGO_DELIVERY_AUDIT_CHANNEL_CAPACITY",
            DEFAULT_DELIVERY_AUDIT_CHANNEL_CAPACITY,
            512,
            262_144,
        );
        let batch_size = parse_env_usize(
            "PUSHGO_DELIVERY_AUDIT_BATCH_SIZE",
            DEFAULT_DELIVERY_AUDIT_BATCH_SIZE,
            16,
            4096,
        );
        let flush_interval_ms = parse_env_u64(
            "PUSHGO_DELIVERY_AUDIT_FLUSH_INTERVAL_MS",
            DEFAULT_DELIVERY_AUDIT_FLUSH_INTERVAL_MS,
            10,
            2000,
        );

        let (tx, rx) = mpsc::channel(channel_capacity);
        tokio::spawn(run_delivery_audit_worker(
            store,
            audit,
            rx,
            batch_size,
            Duration::from_millis(flush_interval_ms),
        ));
        Arc::new(Self {
            enabled: true,
            tx: Some(tx),
        })
    }

    pub(crate) fn enqueue(&self, correlation_id: &str, entry: &DeliveryAuditWrite) {
        if !self.enabled {
            return;
        }
        let Some(tx) = &self.tx else {
            return;
        };
        let queued = DeliveryAuditQueued {
            correlation_id: correlation_id.to_string(),
            entry: entry.clone(),
        };
        match tx.try_send(queued) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

async fn run_delivery_audit_worker(
    store: Store,
    dispatch_audit: Arc<DispatchAuditLog>,
    mut rx: mpsc::Receiver<DeliveryAuditQueued>,
    batch_size: usize,
    flush_interval: Duration,
) {
    let mut ticker = time::interval(flush_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut buffer = Vec::with_capacity(batch_size);

    loop {
        tokio::select! {
            maybe_item = rx.recv() => {
                match maybe_item {
                    Some(item) => {
                        buffer.push(item);
                        if buffer.len() >= batch_size {
                            flush_delivery_audit_batch(&store, &dispatch_audit, &mut buffer).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            flush_delivery_audit_batch(&store, &dispatch_audit, &mut buffer).await;
                        }
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if !buffer.is_empty() {
                    flush_delivery_audit_batch(&store, &dispatch_audit, &mut buffer).await;
                }
            }
        }
    }
}

async fn flush_delivery_audit_batch(
    store: &Store,
    dispatch_audit: &DispatchAuditLog,
    buffer: &mut Vec<DeliveryAuditQueued>,
) {
    let Some(first) = buffer.first() else {
        return;
    };
    let correlation_id = first.correlation_id.clone();
    let batch: Vec<DeliveryAuditWrite> = buffer.iter().map(|item| item.entry.clone()).collect();
    let count = batch.len();
    buffer.clear();
    if let Err(err) = store.append_delivery_audit_batch_async(&batch).await {
        dispatch_audit.record(DispatchAuditRecord {
            stage: "delivery_audit_batch_write_failed",
            correlation_id: correlation_id.as_str(),
            delivery_id: None,
            channel_id: None,
            provider: None,
            platform: None,
            path: None,
            device_token: None,
            success: Some(false),
            status_code: None,
            invalid_token: None,
            payload_too_large: None,
            detail: Some(format!("count={count} error={err}").into()),
        });
    }
}

fn parse_env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn parse_env_u64(key: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::new_store;
    use sqlx::{Row, SqlitePool};
    use tempfile::tempdir;

    fn build_entry(index: usize) -> DeliveryAuditWrite {
        DeliveryAuditWrite {
            delivery_id: format!("d-{index}"),
            channel_id: [7u8; 16],
            device_key: format!("device-{index}"),
            entity_type: Some("message".to_string()),
            entity_id: Some(format!("m-{index}")),
            op_id: Some(format!("op-{index}")),
            path: "provider".to_string(),
            status: "enqueued".to_string(),
            error_code: None,
            created_at: 1_710_000_000 + index as i64,
        }
    }

    #[tokio::test]
    async fn collector_disabled_skips_writes() {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("audit-disabled.sqlite");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        let store = new_store(Some(db_url.as_str()))
            .await
            .expect("store should be created");
        let audit = Arc::new(DispatchAuditLog::new(32, true));
        let collector = DeliveryAuditCollector::spawn(false, Arc::clone(&store), audit);

        for i in 0..8 {
            let entry = build_entry(i);
            collector.enqueue("corr-disabled", &entry);
        }

        tokio::time::sleep(Duration::from_millis(120)).await;

        let pool = SqlitePool::connect(db_url.as_str())
            .await
            .expect("sqlite should open");
        let row = sqlx::query("SELECT COUNT(1) AS count FROM delivery_audit")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
        let count: i64 = row.try_get("count").expect("count column should exist");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn collector_enabled_flushes_batch_to_storage() {
        let dir = tempdir().expect("tempdir should be created");
        let db_path = dir.path().join("audit-enabled.sqlite");
        let db_url = format!("sqlite://{}", db_path.to_string_lossy());
        let store = new_store(Some(db_url.as_str()))
            .await
            .expect("store should be created");
        let audit = Arc::new(DispatchAuditLog::new(32, true));
        let collector = DeliveryAuditCollector::spawn(true, Arc::clone(&store), audit);

        for i in 0..300 {
            let entry = build_entry(i);
            collector.enqueue("corr-enabled", &entry);
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        let pool = SqlitePool::connect(db_url.as_str())
            .await
            .expect("sqlite should open");
        let row = sqlx::query("SELECT COUNT(1) AS count FROM delivery_audit")
            .fetch_one(&pool)
            .await
            .expect("count query should succeed");
        let count: i64 = row.try_get("count").expect("count column should exist");
        assert_eq!(count, 300);
    }
}
