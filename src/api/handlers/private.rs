use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{State, connect_info::ConnectInfo, ws::WebSocketUpgrade},
    http::{HeaderMap, StatusCode, header::SEC_WEBSOCKET_PROTOCOL},
    response::IntoResponse,
};
use serde::Serialize;

use crate::{api::HttpResult, app::AppState};

const PRIVATE_WS_SUBPROTOCOL: &str = "pushgo-private.v1";

#[derive(Debug, Serialize)]
struct PrivateMetricsResponse {
    private_enabled: bool,
    metrics: crate::private::metrics::PrivateMetricsSnapshot,
}

pub(crate) async fn private_metrics(State(state): State<AppState>) -> HttpResult {
    let metrics = state
        .private
        .as_ref()
        .map(|private| private.metrics.snapshot())
        .unwrap_or_else(|| crate::private::metrics::PrivateMetrics::default().snapshot());
    Ok(crate::api::ok(PrivateMetricsResponse {
        private_enabled: state.private_channel_enabled,
        metrics,
    }))
}

pub(crate) async fn private_health(State(state): State<AppState>) -> HttpResult {
    let snapshot = state
        .private
        .as_ref()
        .map(|private| {
            private
                .metrics
                .health_snapshot(state.private_channel_enabled)
        })
        .unwrap_or_else(|| {
            crate::private::metrics::PrivateMetrics::default()
                .health_snapshot(state.private_channel_enabled)
        });
    Ok(crate::api::ok(snapshot))
}

pub(crate) async fn private_ws(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !state.private_channel_enabled {
        return crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
        );
    }
    if !client_offers_ws_subprotocol(&headers, PRIVATE_WS_SUBPROTOCOL) {
        return crate::api::err(
            StatusCode::BAD_REQUEST,
            format!("missing websocket subprotocol `{PRIVATE_WS_SUBPROTOCOL}`"),
        );
    }
    let Some(private_state) = state.private.as_ref() else {
        return crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel runtime is unavailable",
        );
    };
    if state.ip_rate_limit_enabled {
        let client_ip = state.client_ip_resolver.resolve(&headers, Some(peer.ip()));
        if !private_state.rate_limiter.allow_ws_ip(client_ip.as_deref()) {
            return crate::api::err(
                StatusCode::TOO_MANY_REQUESTS,
                "private websocket handshake rate limited",
            );
        }
    }
    let private_state = Arc::clone(private_state);
    ws.protocols([PRIVATE_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            crate::private::ws::serve_ws_socket(socket, private_state).await;
        })
        .into_response()
}

fn client_offers_ws_subprotocol(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|raw| raw.to_str().ok())
        .map(|raw| raw.split(',').map(str::trim).any(|value| value == expected))
        .unwrap_or(false)
}
