//! HTTP discovery and joined WebSocket upgrades for the ordinary Private owner.
use crate::{private_listeners, private_runtime::PrivateRuntime, store::KernelError};
use async_trait::async_trait;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{FutureExt, StreamExt};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, oneshot, watch},
    task::JoinSet,
};
use warp_link::{
    WsUpgradeIo,
    warp_link_core::{ServerConfig, WarpLinkError},
};

struct Inner {
    runtime: PrivateRuntime,
    config: ServerConfig,
    profile: Value,
    upgrades: Arc<Semaphore>,
    tasks: Mutex<JoinSet<()>>,
    stop: watch::Sender<bool>,
}
#[derive(Clone)]
pub struct PrivateHttp(Arc<Inner>);
impl PrivateHttp {
    pub fn new(runtime: PrivateRuntime, config: ServerConfig, profile: Value) -> Self {
        let (stop, _) = watch::channel(false);
        Self(Arc::new(Inner {
            runtime,
            config,
            profile,
            upgrades: Arc::new(Semaphore::new(8192)),
            tasks: Mutex::new(JoinSet::new()),
            stop,
        }))
    }
    pub fn profile(&self) -> Value {
        self.0.profile.clone()
    }
    pub fn wss_enabled(&self) -> bool {
        self.0.profile["transport"]["wss_enabled"].as_bool() == Some(true)
    }
    pub fn upgrade(&self, ws: WebSocketUpgrade, headers: &HeaderMap) -> Response {
        if !self.wss_enabled() || self.0.runtime.is_stopping() {
            return KernelError::Unavailable.into_response();
        }
        let offered = headers
            .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|v| v.trim() == "pushgo-private.v1"));
        if !offered {
            return (StatusCode::BAD_REQUEST, "missing pushgo-private.v1").into_response();
        }
        let Ok(permit) = self.0.upgrades.clone().try_acquire_owned() else {
            return KernelError::Unavailable.into_response();
        };
        // Register ownership synchronously before HTTP 101. Axum's callback only
        // hands over the socket and never owns a detached Private session.
        let (send, receive) = oneshot::channel::<WebSocket>();
        let mut stopped = self.0.stop.subscribe();
        let runtime = self.0.runtime.clone();
        let config = self.0.config.clone();
        let mut tasks = self.0.tasks.lock().unwrap();
        // Serialize with shutdown's JoinSet extraction. An HTTP handler that
        // raced begin_shutdown cannot register a session into a new unjoined set.
        if self.0.runtime.is_stopping() {
            return KernelError::Unavailable.into_response();
        }
        while let Some(result) = tasks.try_join_next() {
            if result.is_err() {
                self.0.runtime.fence("Private WSS session panicked");
                return KernelError::Unavailable.into_response();
            }
        }
        tasks.spawn(async move {
            let _permit=permit;
            let socket=tokio::select! {
                result=tokio::time::timeout(Duration::from_millis(config.hello_timeout_ms),receive)=>match result { Ok(Ok(socket))=>socket,_=>return },
                _=stopped.changed()=>return,
            };
            let write_ms = config.write_timeout_ms;
            // SessionControl expiration ends the real engine, which runs its
            // disconnect cleanup before this joined owning task returns.
            let failure_owner=runtime.clone();
            if AssertUnwindSafe(private_listeners::serve_wss(runtime,config,SocketIo { socket, write_ms })).catch_unwind().await.is_err() {
                failure_owner.fence("Private WSS session panicked");
            }
        });
        ws.protocols(["pushgo-private.v1"])
            .max_frame_size(32770)
            .max_message_size(32770)
            .on_upgrade(move |socket| async move {
                let _ = send.send(socket);
            })
            .into_response()
    }
    /// Call after HTTP acceptance has stopped and its handlers have joined.
    pub async fn shutdown(&self) -> Result<(), KernelError> {
        self.0.runtime.begin_shutdown();
        self.0.stop.send_replace(true);
        let mut tasks = { std::mem::replace(&mut *self.0.tasks.lock().unwrap(), JoinSet::new()) };
        let mut failed = false;
        while let Some(result) = tasks.join_next().await {
            if result.is_err() {
                self.0.runtime.fence("Private WSS join failed");
                failed = true;
            }
        }
        if failed {
            Err(KernelError::Unavailable)
        } else {
            Ok(())
        }
    }
}
struct SocketIo {
    socket: WebSocket,
    write_ms: u64,
}
#[async_trait]
impl WsUpgradeIo for SocketIo {
    async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<(), WarpLinkError> {
        tokio::time::timeout(
            Duration::from_millis(self.write_ms),
            self.socket.send(Message::Binary(bytes.into())),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("Private WSS write timeout".into()))?
        .map_err(|e| WarpLinkError::Transport(e.to_string()))
    }
    async fn recv_binary(&mut self, millis: u64) -> Result<Vec<u8>, WarpLinkError> {
        tokio::time::timeout(Duration::from_millis(millis), async {
            loop {
                match self.socket.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Ok(bytes.to_vec()),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => {
                        return Err(WarpLinkError::Transport(
                            "Private WSS closed or nonbinary frame".into(),
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| WarpLinkError::Timeout("Private WSS read timeout".into()))?
    }
}
pub fn disabled_profile() -> Value {
    json!({"private_channel_enabled":false,"private_enabled":false})
}
/// Same discovery fields as the main Gateway. WSS path is relative to the
/// public base prefix; its absolute URL includes that prefix exactly once.
pub fn discovery_profile(
    public_base_url: &str,
    tcp: Option<SocketAddr>,
    quic: Option<SocketAddr>,
    mqtt: Option<SocketAddr>,
    wss_enabled: bool,
    http_port: u16,
) -> Value {
    let mut transport = json!({
        "quic_enabled":quic.is_some(), "quic_port":quic.map(|a|a.port()),
        "tcp_enabled":tcp.is_some(), "tcp_port":tcp.map_or(0,|a|a.port()),
        "wss_enabled":wss_enabled, "wss_port":http_port, "wss_path":"/private/ws",
        "ws_subprotocol":"pushgo-private.v1",
        "mqtt_enabled":mqtt.is_some(), "mqtt_port":mqtt.map(|a|a.port()),
        "mqtt_tls_required":false, "mqtt_protocol":"mqtt5", "mqtt_qos":1,
        "mqtt_topic_template":"{channel_id}"
    });
    if wss_enabled {
        let base = public_base_url.trim_end_matches('/');
        let base = base
            .strip_prefix("https://")
            .map(|s| format!("wss://{s}"))
            .or_else(|| base.strip_prefix("http://").map(|s| format!("ws://{s}")));
        if let Some(base) = base {
            transport["wss_url"] = json!(format!("{base}/private/ws"));
        }
    }
    json!({"private_channel_enabled":true,"private_enabled":true,"transport":transport})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_retains_main_gateway_fields_and_tcp_only_actual_port() {
        let profile = discovery_profile(
            "http://127.0.0.1:4400/prefix",
            Some("127.0.0.1:4401".parse().unwrap()),
            None,
            None,
            false,
            4400,
        );
        assert_eq!(profile["private_channel_enabled"], true);
        assert_eq!(profile["private_enabled"], true);
        let t = &profile["transport"];
        assert_eq!(t["tcp_enabled"], true);
        assert_eq!(t["tcp_port"], 4401);
        assert_eq!(t["quic_enabled"], false);
        assert!(t["quic_port"].is_null());
        assert_eq!(t["wss_enabled"], false);
        assert!(t.get("wss_url").is_none());
        assert_eq!(t["ws_subprotocol"], "pushgo-private.v1");
        assert_eq!(t["mqtt_protocol"], "mqtt5");
        assert_eq!(t["mqtt_qos"], 1);
    }
    #[test]
    fn profile_wss_url_preserves_prefix_and_disabled_profile_omits_transport() {
        let p = discovery_profile(
            "http://127.0.0.1:4400/prefix/",
            None,
            None,
            None,
            true,
            4400,
        );
        assert_eq!(
            p["transport"]["wss_url"],
            "ws://127.0.0.1:4400/prefix/private/ws"
        );
        assert_eq!(p["transport"]["wss_path"], "/private/ws");
        assert_eq!(
            disabled_profile(),
            json!({"private_channel_enabled":false,"private_enabled":false})
        );
    }
}
