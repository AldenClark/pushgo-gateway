use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use serde::Serialize;

#[derive(Default)]
pub struct PrivateMetrics {
    quic_connect_attempts: AtomicU64,
    quic_connect_success: AtomicU64,
    quic_connect_failures: AtomicU64,
    wss_connect_attempts: AtomicU64,
    wss_connect_success: AtomicU64,
    wss_connect_failures: AtomicU64,
    tcp_connect_attempts: AtomicU64,
    tcp_connect_success: AtomicU64,
    tcp_connect_failures: AtomicU64,
    hello_timeouts: AtomicU64,
    auth_failures: AtomicU64,
    auth_expired_sessions: AtomicU64,
    auth_revoked_sessions: AtomicU64,
    auth_refresh_required: AtomicU64,
    idle_timeouts: AtomicU64,
    frames_deliver_sent: AtomicU64,
    frames_deliver_retransmit_sent: AtomicU64,
    frames_deliver_retransmit_exhausted: AtomicU64,
    frames_deliver_send_failures: AtomicU64,
    frames_ack_ok: AtomicU64,
    frames_ack_non_ok: AtomicU64,
    fallback_scanned: AtomicU64,
    fallback_sent: AtomicU64,
    fallback_deferred: AtomicU64,
    fallback_dropped: AtomicU64,
    task_queue_depth: AtomicU64,
    task_lag_ms: AtomicU64,
    enqueue_failures: AtomicU64,
    replay_bootstrap_enqueued: AtomicU64,
    last_error_at: AtomicI64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateMetricsSnapshot {
    pub quic_connect_attempts: u64,
    pub quic_connect_success: u64,
    pub quic_connect_failures: u64,
    pub wss_connect_attempts: u64,
    pub wss_connect_success: u64,
    pub wss_connect_failures: u64,
    pub tcp_connect_attempts: u64,
    pub tcp_connect_success: u64,
    pub tcp_connect_failures: u64,
    pub hello_timeouts: u64,
    pub auth_failures: u64,
    pub auth_expired_sessions: u64,
    pub auth_revoked_sessions: u64,
    pub auth_refresh_required: u64,
    pub idle_timeouts: u64,
    pub frames_deliver_sent: u64,
    pub frames_deliver_retransmit_sent: u64,
    pub frames_deliver_retransmit_exhausted: u64,
    pub frames_deliver_send_failures: u64,
    pub frames_ack_ok: u64,
    pub frames_ack_non_ok: u64,
    pub fallback_scanned: u64,
    pub fallback_sent: u64,
    pub fallback_deferred: u64,
    pub fallback_dropped: u64,
    pub task_queue_depth: u64,
    pub task_lag_ms: u64,
    pub enqueue_failures: u64,
    pub replay_bootstrap_enqueued: u64,
    pub last_error_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateAlert {
    pub code: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateHealthSnapshot {
    pub status: String,
    pub alerts: Vec<PrivateAlert>,
    pub metrics: PrivateMetricsSnapshot,
}

impl PrivateMetrics {
    pub fn reset(&self) {
        self.quic_connect_attempts.store(0, Ordering::Relaxed);
        self.quic_connect_success.store(0, Ordering::Relaxed);
        self.quic_connect_failures.store(0, Ordering::Relaxed);
        self.wss_connect_attempts.store(0, Ordering::Relaxed);
        self.wss_connect_success.store(0, Ordering::Relaxed);
        self.wss_connect_failures.store(0, Ordering::Relaxed);
        self.tcp_connect_attempts.store(0, Ordering::Relaxed);
        self.tcp_connect_success.store(0, Ordering::Relaxed);
        self.tcp_connect_failures.store(0, Ordering::Relaxed);
        self.hello_timeouts.store(0, Ordering::Relaxed);
        self.auth_failures.store(0, Ordering::Relaxed);
        self.auth_expired_sessions.store(0, Ordering::Relaxed);
        self.auth_revoked_sessions.store(0, Ordering::Relaxed);
        self.auth_refresh_required.store(0, Ordering::Relaxed);
        self.idle_timeouts.store(0, Ordering::Relaxed);
        self.frames_deliver_sent.store(0, Ordering::Relaxed);
        self.frames_deliver_retransmit_sent
            .store(0, Ordering::Relaxed);
        self.frames_deliver_retransmit_exhausted
            .store(0, Ordering::Relaxed);
        self.frames_deliver_send_failures
            .store(0, Ordering::Relaxed);
        self.frames_ack_ok.store(0, Ordering::Relaxed);
        self.frames_ack_non_ok.store(0, Ordering::Relaxed);
        self.fallback_scanned.store(0, Ordering::Relaxed);
        self.fallback_sent.store(0, Ordering::Relaxed);
        self.fallback_deferred.store(0, Ordering::Relaxed);
        self.fallback_dropped.store(0, Ordering::Relaxed);
        self.task_queue_depth.store(0, Ordering::Relaxed);
        self.task_lag_ms.store(0, Ordering::Relaxed);
        self.enqueue_failures.store(0, Ordering::Relaxed);
        self.replay_bootstrap_enqueued.store(0, Ordering::Relaxed);
        self.last_error_at.store(0, Ordering::Relaxed);
    }

    pub fn mark_quic_connect_attempt(&self) {
        self.quic_connect_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_quic_connect_success(&self) {
        self.quic_connect_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_quic_connect_failure(&self) {
        self.quic_connect_failures.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_wss_connect_attempt(&self) {
        self.wss_connect_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_wss_connect_success(&self) {
        self.wss_connect_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_wss_connect_failure(&self) {
        self.wss_connect_failures.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_tcp_connect_attempt(&self) {
        self.tcp_connect_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_tcp_connect_success(&self) {
        self.tcp_connect_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_tcp_connect_failure(&self) {
        self.tcp_connect_failures.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_hello_timeout(&self) {
        self.hello_timeouts.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_auth_expired(&self) {
        self.auth_expired_sessions.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_auth_revoked(&self) {
        self.auth_revoked_sessions.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_auth_refresh_required(&self) {
        self.auth_refresh_required.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_idle_timeout(&self) {
        self.idle_timeouts.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_deliver_sent(&self) {
        self.frames_deliver_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_deliver_retransmit_sent(&self) {
        self.frames_deliver_retransmit_sent
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_retransmit_exhausted(&self, count: usize) {
        self.frames_deliver_retransmit_exhausted
            .fetch_add(count as u64, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_deliver_send_failure(&self) {
        self.frames_deliver_send_failures
            .fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_ack_ok(&self) {
        self.frames_ack_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_ack_non_ok(&self) {
        self.frames_ack_non_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn mark_fallback_tick(&self, scanned: usize, sent: usize, deferred: usize, dropped: usize) {
        self.fallback_scanned
            .fetch_add(scanned as u64, Ordering::Relaxed);
        self.fallback_sent.fetch_add(sent as u64, Ordering::Relaxed);
        self.fallback_deferred
            .fetch_add(deferred as u64, Ordering::Relaxed);
        self.fallback_dropped
            .fetch_add(dropped as u64, Ordering::Relaxed);
        if dropped > 0 {
            self.mark_error();
        }
    }

    pub fn mark_task_queue_depth(&self, depth: usize) {
        self.task_queue_depth.store(depth as u64, Ordering::Relaxed);
    }

    pub fn mark_task_lag_ms(&self, lag_ms: u64) {
        self.task_lag_ms.store(lag_ms, Ordering::Relaxed);
    }

    pub fn mark_enqueue_failure(&self) {
        self.enqueue_failures.fetch_add(1, Ordering::Relaxed);
        self.mark_error();
    }

    pub fn mark_replay_bootstrap_enqueued(&self, count: usize) {
        self.replay_bootstrap_enqueued
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> PrivateMetricsSnapshot {
        let last_error = self.last_error_at.load(Ordering::Relaxed);
        PrivateMetricsSnapshot {
            quic_connect_attempts: self.quic_connect_attempts.load(Ordering::Relaxed),
            quic_connect_success: self.quic_connect_success.load(Ordering::Relaxed),
            quic_connect_failures: self.quic_connect_failures.load(Ordering::Relaxed),
            wss_connect_attempts: self.wss_connect_attempts.load(Ordering::Relaxed),
            wss_connect_success: self.wss_connect_success.load(Ordering::Relaxed),
            wss_connect_failures: self.wss_connect_failures.load(Ordering::Relaxed),
            tcp_connect_attempts: self.tcp_connect_attempts.load(Ordering::Relaxed),
            tcp_connect_success: self.tcp_connect_success.load(Ordering::Relaxed),
            tcp_connect_failures: self.tcp_connect_failures.load(Ordering::Relaxed),
            hello_timeouts: self.hello_timeouts.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            auth_expired_sessions: self.auth_expired_sessions.load(Ordering::Relaxed),
            auth_revoked_sessions: self.auth_revoked_sessions.load(Ordering::Relaxed),
            auth_refresh_required: self.auth_refresh_required.load(Ordering::Relaxed),
            idle_timeouts: self.idle_timeouts.load(Ordering::Relaxed),
            frames_deliver_sent: self.frames_deliver_sent.load(Ordering::Relaxed),
            frames_deliver_retransmit_sent: self
                .frames_deliver_retransmit_sent
                .load(Ordering::Relaxed),
            frames_deliver_retransmit_exhausted: self
                .frames_deliver_retransmit_exhausted
                .load(Ordering::Relaxed),
            frames_deliver_send_failures: self.frames_deliver_send_failures.load(Ordering::Relaxed),
            frames_ack_ok: self.frames_ack_ok.load(Ordering::Relaxed),
            frames_ack_non_ok: self.frames_ack_non_ok.load(Ordering::Relaxed),
            fallback_scanned: self.fallback_scanned.load(Ordering::Relaxed),
            fallback_sent: self.fallback_sent.load(Ordering::Relaxed),
            fallback_deferred: self.fallback_deferred.load(Ordering::Relaxed),
            fallback_dropped: self.fallback_dropped.load(Ordering::Relaxed),
            task_queue_depth: self.task_queue_depth.load(Ordering::Relaxed),
            task_lag_ms: self.task_lag_ms.load(Ordering::Relaxed),
            enqueue_failures: self.enqueue_failures.load(Ordering::Relaxed),
            replay_bootstrap_enqueued: self.replay_bootstrap_enqueued.load(Ordering::Relaxed),
            last_error_at: (last_error > 0).then_some(last_error),
        }
    }

    pub fn health_snapshot(&self, private_enabled: bool) -> PrivateHealthSnapshot {
        let metrics = self.snapshot();
        let mut alerts = Vec::new();
        if private_enabled {
            let connect_failures = metrics.quic_connect_failures
                + metrics.tcp_connect_failures
                + metrics.wss_connect_failures;
            let connect_success = metrics.quic_connect_success
                + metrics.tcp_connect_success
                + metrics.wss_connect_success;
            if connect_failures >= 5 && connect_success == 0 {
                alerts.push(PrivateAlert {
                    code: "transport_unavailable".to_string(),
                    severity: "critical".to_string(),
                    message: "private channel cannot establish transport connections".to_string(),
                });
            }
            if metrics.frames_deliver_send_failures >= 10 {
                alerts.push(PrivateAlert {
                    code: "deliver_backpressure".to_string(),
                    severity: "warning".to_string(),
                    message: "deliver send failures are elevated; check client receive speed"
                        .to_string(),
                });
            }
            if metrics.frames_deliver_retransmit_exhausted > 0 {
                alerts.push(PrivateAlert {
                    code: "retransmit_exhausted".to_string(),
                    severity: "warning".to_string(),
                    message: format!(
                        "{} deliveries exceeded retransmit max retries",
                        metrics.frames_deliver_retransmit_exhausted
                    ),
                });
            }
            if metrics.fallback_dropped > 0 {
                alerts.push(PrivateAlert {
                    code: "fallback_drop".to_string(),
                    severity: "warning".to_string(),
                    message: format!(
                        "{} private messages reached fallback max attempts and were dropped",
                        metrics.fallback_dropped
                    ),
                });
            }
            if metrics.enqueue_failures >= 10 {
                alerts.push(PrivateAlert {
                    code: "enqueue_failure_high".to_string(),
                    severity: "warning".to_string(),
                    message: format!(
                        "private enqueue failures are elevated: {}",
                        metrics.enqueue_failures
                    ),
                });
            }
            if metrics.auth_failures >= 20 {
                alerts.push(PrivateAlert {
                    code: "auth_failure_high".to_string(),
                    severity: "warning".to_string(),
                    message: format!(
                        "private auth failures are elevated: {}",
                        metrics.auth_failures
                    ),
                });
            }
            let ack_total = metrics.frames_ack_ok + metrics.frames_ack_non_ok;
            if ack_total >= 20 {
                let ack_ok_ratio = metrics.frames_ack_ok as f64 / ack_total as f64;
                if ack_ok_ratio < 0.90 {
                    alerts.push(PrivateAlert {
                        code: "ack_quality_low".to_string(),
                        severity: "warning".to_string(),
                        message: format!("ack ok ratio is low: {:.2}%", ack_ok_ratio * 100.0),
                    });
                }
            }
        }
        let status = if alerts.iter().any(|a| a.severity == "critical") {
            "unhealthy"
        } else if alerts.is_empty() {
            "healthy"
        } else {
            "degraded"
        };
        PrivateHealthSnapshot {
            status: status.to_string(),
            alerts,
            metrics,
        }
    }

    fn mark_error(&self) {
        self.last_error_at
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }
}
