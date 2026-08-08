use std::{sync::Arc, time::Duration};

use axum::{
    extract::{State, ws::WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tokio::time::Instant;
use tracing::Instrument;

use crate::{api::HttpResult, app::AppState};

mod network;
mod runtime;

const PRIVATE_WS_SUBPROTOCOL: &str = "pushgo-private.v1";

pub(crate) async fn gateway_profile(State(state): State<AppState>) -> HttpResult {
    Ok(crate::api::ok(
        runtime::PrivateRuntimeView::new(&state).gateway_profile_response(),
    ))
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
    if private_state.is_shutting_down() {
        emit_private_ws_rejected("runtime_shutting_down");
        return crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private runtime is shutting down",
            "private_runtime_shutting_down",
        );
    }
    let Some(session_permit) = private_state.try_acquire_session_admission() else {
        emit_private_ws_rejected("global_session_limit");
        return crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private session capacity is exhausted",
            "private_session_capacity_exhausted",
        );
    };
    let Some(handshake_permit) = private_state.try_acquire_handshake_admission() else {
        emit_private_ws_rejected("global_handshake_limit");
        return crate::api::err_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "private handshake capacity is exhausted",
            "private_handshake_capacity_exhausted",
        );
    };
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "private.ws_upgrade_accepted"
    );
    let private_state = Arc::clone(private_state);
    let handshake_deadline = Instant::now()
        + Duration::from_millis(
            crate::private::warp_engine::default_server_config()
                .hello_timeout_ms
                .max(1),
        );
    let upgrade_span = tracing::info_span!("gateway.private.ws.upgrade");
    ws.protocols([PRIVATE_WS_SUBPROTOCOL])
        .max_frame_size(crate::private::ws::MAX_WSS_FRAME_BYTES)
        .max_message_size(crate::private::ws::MAX_WSS_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            crate::private::ws::serve_ws_socket(
                socket,
                private_state,
                session_permit,
                handshake_permit,
                handshake_deadline,
            )
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
