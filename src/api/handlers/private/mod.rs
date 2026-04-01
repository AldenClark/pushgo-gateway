use std::sync::Arc;

use axum::{
    extract::{State, connect_info::ConnectInfo, ws::WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

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

pub(crate) async fn private_network_diagnostics(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> HttpResult {
    if !state.private_channel_enabled {
        return Ok(crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
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
    if !state.private_channel_enabled {
        return crate::api::err(
            StatusCode::SERVICE_UNAVAILABLE,
            "private channel is disabled",
        );
    }
    if !network::PrivateRequestHeaders::new(&headers).offers_ws_subprotocol(PRIVATE_WS_SUBPROTOCOL)
    {
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
    let private_state = Arc::clone(private_state);
    ws.protocols([PRIVATE_WS_SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            crate::private::ws::serve_ws_socket(socket, private_state).await;
        })
        .into_response()
}

#[cfg(test)]
mod tests;
