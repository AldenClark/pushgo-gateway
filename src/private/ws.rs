use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use tokio::time::timeout;
use tracing::Instrument;
use warp_link::warp_link_core::WarpLinkError;
use warp_link::{WsUpgradeIo, serve_wss_embedded};

use crate::private::{
    PrivateState,
    warp_engine::{PushgoServerApp, default_server_config},
};

const MAX_WSS_FRAME_BYTES: usize = (32 * 1024) + 2;

pub async fn serve_ws_socket(socket: WebSocket, state: Arc<PrivateState>) {
    let span = tracing::info_span!("gateway.private.wss.session");
    async move {
        let app = PushgoServerApp::new(Arc::clone(&state));
        let io = AxumWsIo::new(socket);
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.wss_session_started"
        );
        if let Err(err) = serve_wss_embedded(default_server_config(), app, io).await {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::WARN,
                event = "private.wss_session_terminated_with_error",
                error = %(err.to_string())
            );
        }
        ::tracing::event!(
            target: "gateway.trace_event",
            ::tracing::Level::INFO,
            event = "private.wss_session_finished"
        );
    }
    .instrument(span)
    .await;
}

struct AxumWsIo {
    send: SplitSink<WebSocket, Message>,
    recv: SplitStream<WebSocket>,
}

impl AxumWsIo {
    fn new(socket: WebSocket) -> Self {
        let (send, recv) = socket.split();
        Self { send, recv }
    }
}

#[async_trait]
impl WsUpgradeIo for AxumWsIo {
    async fn send_binary(&mut self, frame: Vec<u8>) -> Result<(), WarpLinkError> {
        self.send
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|e| {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "private.wss_send_failed",
                    error = %(e.to_string())
                );
                WarpLinkError::Transport(e.to_string())
            })
    }

    async fn recv_binary(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        loop {
            let next = timeout(Duration::from_millis(timeout_ms), self.recv.next())
                .await
                .map_err(|_| {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::INFO,
                        event = "private.wss_recv_timeout",
                        timeout_ms = (timeout_ms)
                    );
                    WarpLinkError::Timeout("wss read timeout".to_string())
                })?;
            let message = next
                .ok_or_else(|| {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::INFO,
                        event = "private.wss_recv_closed"
                    );
                    WarpLinkError::Transport("websocket closed".to_string())
                })?
                .map_err(|e| {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "private.wss_recv_failed",
                        error = %(e.to_string())
                    );
                    WarpLinkError::Transport(e.to_string())
                })?;
            match message {
                Message::Binary(data) => {
                    if data.len() > MAX_WSS_FRAME_BYTES {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "private.wss_recv_rejected",
                            reason = %("frame_too_large"),
                            frame_bytes = (data.len() as u64)
                        );
                        return Err(WarpLinkError::Protocol(format!(
                            "wss frame too large: {}",
                            data.len()
                        )));
                    }
                    return Ok(data.to_vec());
                }
                Message::Ping(payload) => {
                    self.send.send(Message::Pong(payload)).await.map_err(|e| {
                        ::tracing::event!(
                            target: "gateway.trace_event",
                            ::tracing::Level::WARN,
                            event = "private.wss_pong_send_failed",
                            error = %(e.to_string())
                        );
                        WarpLinkError::Transport(e.to_string())
                    })?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::INFO,
                        event = "private.wss_recv_closed"
                    );
                    return Err(WarpLinkError::Transport("websocket closed".to_string()));
                }
                Message::Text(_) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "private.wss_recv_rejected",
                        reason = %("text_frame_not_supported")
                    );
                    return Err(WarpLinkError::Protocol(
                        "wss text frame is not supported".to_string(),
                    ));
                }
            }
        }
    }
}
