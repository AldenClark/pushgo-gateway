use std::sync::Arc;

use axum::{
    extract::{State, connect_info::ConnectInfo, ws::WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tracing::Instrument;

use crate::{api::HttpResult, app::AppState};

mod network;
mod runtime;

const PRIVATE_WS_SUBPROTOCOL: &str = "pushgo-private.v1";

pub(crate) async fn private_metrics(State(state): State<AppState>) -> HttpResult {
    Ok(crate::api::ok(
        runtime::PrivateRuntimeView::new(&state).metrics_response(),
    ))
}

pub(crate) async fn private_health(State(state): State<AppState>) -> HttpResult {
    Ok(crate::api::ok(
        runtime::PrivateRuntimeView::new(&state).health_snapshot(),
    ))
}

pub(crate) async fn gateway_profile(State(state): State<AppState>) -> HttpResult {
    Ok(crate::api::ok(
        runtime::PrivateRuntimeView::new(&state).gateway_profile_response(),
    ))
}

pub(crate) async fn private_memory(State(state): State<AppState>) -> HttpResult {
    let private_outbox_total = if state.private_channel_enabled {
        state.store.count_private_outbox_total().await.ok()
    } else {
        None
    };
    Ok(crate::api::ok(
        runtime::PrivateRuntimeView::new(&state).memory_response(private_outbox_total),
    ))
}

pub(crate) async fn private_network_diagnostics(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> HttpResult {
    if !state.private_channel_enabled {
        return Ok(crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
            "private_channel_disabled",
        ));
    }

    let runtime_view = runtime::PrivateRuntimeView::new(&state);
    let request = network::PrivateDiagnosticsRequest::new(peer, &headers);
    Ok(crate::api::ok(request.diagnostics_response(&runtime_view)))
}

pub(crate) async fn private_ws(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if !state.private_transport_profile.wss_enabled {
        emit_private_ws_rejected("wss_transport_disabled");
        return crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private wss transport is disabled",
            "private_wss_transport_disabled",
        );
    }
    if !state.private_channel_enabled {
        emit_private_ws_rejected("private_channel_disabled");
        return crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
            "private_channel_disabled",
        );
    }
    if !network::PrivateRequestHeaders::new(&headers).offers_ws_subprotocol(PRIVATE_WS_SUBPROTOCOL)
    {
        emit_private_ws_rejected("missing_subprotocol");
        return crate::api::err_with_code(
            StatusCode::BAD_REQUEST,
            format!("missing websocket subprotocol `{PRIVATE_WS_SUBPROTOCOL}`"),
            "missing_websocket_subprotocol",
        );
    }
    let Some(private_state) = state.private.as_ref() else {
        emit_private_ws_rejected("private_runtime_unavailable");
        return crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel runtime is unavailable",
            "private_channel_runtime_unavailable",
        );
    };
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "private.ws_upgrade_accepted"
    );
    let private_state = Arc::clone(private_state);
    let upgrade_span = tracing::info_span!("gateway.private.ws.upgrade");
    ws.protocols([PRIVATE_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            crate::private::ws::serve_ws_socket(socket, private_state)
                .instrument(upgrade_span)
                .await;
        })
        .into_response()
}

fn emit_private_ws_rejected(reason: &'static str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "private.ws_upgrade_rejected",
        reason = %(reason)
    );
}

#[cfg(test)]
mod tests;
