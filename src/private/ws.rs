use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use tokio::time::timeout;
use warp_link::warp_link_core::WarpLinkError;
use warp_link::{WsUpgradeIo, serve_wss_embedded};

use crate::private::{
    PrivateState,
    warp_engine::{PushgoServerApp, default_server_config},
};

const MAX_WSS_FRAME_BYTES: usize = (32 * 1024) + 2;

pub async fn serve_ws_socket(socket: WebSocket, state: Arc<PrivateState>) {
    let app = PushgoServerApp::new(Arc::clone(&state));
    let io = AxumWsIo::new(socket);
    if let Err(err) = serve_wss_embedded(default_server_config(), app, io).await {
        crate::util::TraceEvent::new("private.wss_session_terminated_with_error")
            .field_str("error", err.to_string())
            .emit();
    }
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
            .map_err(|e| WarpLinkError::Transport(e.to_string()))
    }

    async fn recv_binary(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        loop {
            let next = timeout(Duration::from_millis(timeout_ms), self.recv.next())
                .await
                .map_err(|_| WarpLinkError::Timeout("wss read timeout".to_string()))?;
            let message = next
                .ok_or_else(|| WarpLinkError::Transport("websocket closed".to_string()))?
                .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
            match message {
                Message::Binary(data) => {
                    if data.len() > MAX_WSS_FRAME_BYTES {
                        return Err(WarpLinkError::Protocol(format!(
                            "wss frame too large: {}",
                            data.len()
                        )));
                    }
                    return Ok(data.to_vec());
                }
                Message::Ping(payload) => {
                    self.send
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => {
                    return Err(WarpLinkError::Transport("websocket closed".to_string()));
                }
                Message::Text(_) => {
                    return Err(WarpLinkError::Protocol(
                        "wss text frame is not supported".to_string(),
                    ));
                }
            }
        }
    }
}
