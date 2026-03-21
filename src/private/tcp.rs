use std::sync::Arc;

use warp_link::warp_link_core::TlsMode;
use warp_link::{serve_tcp as warp_serve_tcp, serve_tcp_plain as warp_serve_tcp_plain};

use crate::private::{
    PrivateState,
    warp_engine::{PushgoServerApp, default_server_config},
};

pub async fn serve_tcp_tls(
    bind_addr: &str,
    cert_path: &str,
    key_path: &str,
    state: Arc<PrivateState>,
) -> Result<(), String> {
    let app = PushgoServerApp::new(state);
    let mut config = default_server_config();
    config.tcp_listen_addr = Some(bind_addr.to_string());
    config.tls_cert_path = Some(cert_path.to_string());
    config.tls_key_path = Some(key_path.to_string());
    config.tcp_alpn = "pushgo-tcp".to_string();
    config.tcp_tls_mode = TlsMode::TerminateInWarp;
    warp_serve_tcp(config, app).await.map_err(|e| e.to_string())
}

pub async fn serve_tcp_plain(bind_addr: &str, state: Arc<PrivateState>) -> Result<(), String> {
    let app = PushgoServerApp::new(state);
    let mut config = default_server_config();
    config.tcp_listen_addr = Some(bind_addr.to_string());
    config.tcp_alpn = "pushgo-tcp".to_string();
    config.tcp_tls_mode = TlsMode::OffloadAtEdge;
    config.tls_cert_path = None;
    config.tls_key_path = None;
    warp_serve_tcp_plain(config, app)
        .await
        .map_err(|e| e.to_string())
}
