use std::sync::Arc;

use warp_link::serve_quic as warp_serve_quic;

use crate::private::{
    PrivateState,
    warp_engine::{PushgoServerApp, default_server_config},
};

pub async fn serve_quic(
    bind_addr: &str,
    cert_path: &str,
    key_path: &str,
    state: Arc<PrivateState>,
) -> Result<(), String> {
    let app = PushgoServerApp::new(state);
    let mut config = default_server_config();
    config.quic_listen_addr = Some(bind_addr.to_string());
    config.tls_cert_path = Some(cert_path.to_string());
    config.tls_key_path = Some(key_path.to_string());
    config.quic_alpn = "pushgo-quic".to_string();
    warp_serve_quic(config, app)
        .await
        .map_err(|e| e.to_string())
}
