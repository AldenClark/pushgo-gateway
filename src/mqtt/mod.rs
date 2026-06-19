use std::sync::Arc;

use crate::{app::AppState, private::PrivateState};

mod dedupe;
mod payload;
mod roles;
mod server;
mod topics;

pub(crate) use dedupe::{MqttPublishDedupe, MqttPublishDedupeDecision, MqttPublishDedupeKey};
pub(crate) use payload::{MqttDeliveryEnvelope, MqttPublishCommand, MqttPublishEnvelope};
pub(crate) use roles::MqttRole;
pub use server::{serve_mqtt, serve_mqtt_tls};
pub(crate) use topics::MqttMessageTopic;

#[derive(Debug, Clone)]
pub struct MqttConfig {
    pub bind_addr: String,
    pub advertised_port: u16,
    pub max_packet_bytes: usize,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Clone)]
pub(crate) struct MqttRuntime {
    pub state: Arc<AppState>,
    pub private: Arc<PrivateState>,
    pub config: MqttConfig,
    pub publish_dedupe: Arc<MqttPublishDedupe>,
}

pub(crate) fn spawn_mqtt(state: Arc<AppState>, private: Arc<PrivateState>, config: MqttConfig) {
    let bind_addr = config.bind_addr.clone();
    tokio::spawn(async move {
        let mut restart_delay_secs = 1u64;
        loop {
            let runtime = MqttRuntime {
                state: Arc::clone(&state),
                private: Arc::clone(&private),
                config: config.clone(),
                publish_dedupe: MqttPublishDedupe::new(),
            };
            let result = if runtime.config.tls_enabled {
                match mqtt_tls_acceptor(&runtime.config) {
                    Ok(acceptor) => serve_mqtt_tls(runtime, acceptor).await,
                    Err(err) => Err(err),
                }
            } else {
                serve_mqtt(runtime).await
            };
            if let Err(err) = result {
                ::tracing::event!(
                    target: "gateway.trace_event",
                    ::tracing::Level::WARN,
                    event = "mqtt.serve_failed",
                    bind_addr = %(bind_addr.as_str()),
                    retry_delay_secs = (restart_delay_secs),
                    error = %(err)
                );
            }
            if private.is_shutting_down() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(restart_delay_secs)) => {}
                _ = private.wait_for_shutdown() => break,
            }
            restart_delay_secs = restart_delay_secs.saturating_mul(2).min(30);
        }
    });
}

fn mqtt_tls_acceptor(config: &MqttConfig) -> Result<tokio_rustls::TlsAcceptor, String> {
    let cert_path = config.tls_cert_path.as_deref().ok_or_else(|| {
        "PUSHGO_PRIVATE_TLS_CERT is required when MQTT TLS is enabled".to_string()
    })?;
    let key_path = config
        .tls_key_path
        .as_deref()
        .ok_or_else(|| "PUSHGO_PRIVATE_TLS_KEY is required when MQTT TLS is enabled".to_string())?;
    crate::private::tls::ServerTlsIdentity::load(cert_path, key_path)?.into_acceptor("mqtt", "mqtt")
}
