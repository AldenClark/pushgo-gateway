use axum::{extract::State, http::StatusCode};
use serde::Serialize;

use crate::{api::HttpResult, app::AppState, private::metrics::PrivateHealthSnapshot};

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    private_channel_enabled: bool,
    private_runtime_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_health_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_last_accept_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ReadinessResponse {
    status: &'static str,
    private_channel_enabled: bool,
    private_runtime_ready: bool,
}

#[derive(Debug, Serialize)]
struct GenericReadinessResponse {
    status: &'static str,
}

pub(crate) async fn healthz(State(state): State<AppState>) -> HttpResult {
    let private_runtime_ready = !state.private_channel_enabled || state.private.is_some();
    if !private_runtime_ready {
        return Ok(crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private runtime unavailable",
        ));
    }

    let private_health_status = state.private.as_ref().map(|private| {
        private
            .metrics
            .health_snapshot(state.private_channel_enabled)
    });
    let private_last_accept_at = private_health_status
        .as_ref()
        .and_then(|snapshot| snapshot.metrics.last_accept_at);
    let private_alive = private_channel_alive(private_health_status.as_ref());
    if private_alive {
        return Ok(crate::api::ok(HealthResponse {
            status: "ok",
            private_channel_enabled: state.private_channel_enabled,
            private_runtime_ready,
            private_health_status: private_health_status.map(|snapshot| snapshot.status),
            private_last_accept_at,
        }));
    }
    Ok(crate::api::err(
        StatusCode::SERVICE_UNAVAILABLE,
        "private channel unhealthy",
    ))
}

fn private_channel_alive(snapshot: Option<&PrivateHealthSnapshot>) -> bool {
    let Some(snapshot) = snapshot else {
        return true;
    };
    if snapshot.status == "unhealthy" {
        return false;
    }
    let transport_attempts = snapshot.metrics.quic_connect_attempts
        + snapshot.metrics.tcp_connect_attempts
        + snapshot.metrics.wss_connect_attempts;
    let transport_success = snapshot.metrics.quic_connect_success
        + snapshot.metrics.tcp_connect_success
        + snapshot.metrics.wss_connect_success;
    let handshake_stuck = transport_attempts >= 10
        && transport_success == 0
        && snapshot.metrics.last_accept_at.is_none();
    !handshake_stuck
}

pub(crate) async fn readyz(State(_state): State<AppState>) -> HttpResult {
    Ok(crate::api::ok(GenericReadinessResponse { status: "ok" }))
}

pub(crate) async fn private_readyz(State(state): State<AppState>) -> HttpResult {
    let private_runtime_ready = state.private_channel_enabled && state.private.is_some();
    if private_runtime_ready {
        return Ok(crate::api::ok(ReadinessResponse {
            status: "ok",
            private_channel_enabled: true,
            private_runtime_ready,
        }));
    }
    Ok(crate::api::err(
        StatusCode::SERVICE_UNAVAILABLE,
        "private runtime unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use crate::private::metrics::{PrivateHealthSnapshot, PrivateMetricsSnapshot};

    fn snapshot(
        status: &str,
        attempts: u64,
        success: u64,
        last_accept_at: Option<i64>,
    ) -> PrivateHealthSnapshot {
        PrivateHealthSnapshot {
            status: status.to_string(),
            alerts: Vec::new(),
            metrics: PrivateMetricsSnapshot {
                quic_connect_attempts: attempts,
                quic_connect_success: success,
                quic_connect_failures: 0,
                wss_connect_attempts: 0,
                wss_connect_success: 0,
                wss_connect_failures: 0,
                tcp_connect_attempts: 0,
                tcp_connect_success: 0,
                tcp_connect_failures: 0,
                hello_timeouts: 0,
                auth_failures: 0,
                auth_expired_sessions: 0,
                auth_revoked_sessions: 0,
                auth_refresh_required: 0,
                idle_timeouts: 0,
                frames_deliver_sent: 0,
                frames_deliver_retransmit_sent: 0,
                frames_deliver_retransmit_exhausted: 0,
                frames_deliver_send_failures: 0,
                frames_ack_ok: 0,
                frames_ack_non_ok: 0,
                fallback_scanned: 0,
                fallback_sent: 0,
                fallback_deferred: 0,
                fallback_dropped: 0,
                task_queue_depth: 0,
                task_lag_ms: 0,
                enqueue_failures: 0,
                replay_bootstrap_enqueued: 0,
                last_accept_at,
                last_error_at: None,
            },
        }
    }

    #[test]
    fn private_channel_alive_rejects_handshake_stuck_state() {
        let snap = snapshot("healthy", 10, 0, None);
        assert!(!super::private_channel_alive(Some(&snap)));
    }

    #[test]
    fn private_channel_alive_accepts_when_success_exists() {
        let snap = snapshot("healthy", 10, 1, Some(1_700_000_000));
        assert!(super::private_channel_alive(Some(&snap)));
    }
}
