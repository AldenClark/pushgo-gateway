use std::{net::SocketAddr, pin::Pin};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use super::MqttSession;
use crate::mqtt::MqttRuntime;

pub(super) struct MqttStream {
    pub(super) reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
    pub(super) writer: Pin<Box<dyn AsyncWrite + Send + Sync>>,
}

impl MqttStream {
    pub(super) fn boxed<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
        }
    }
}

pub async fn serve_mqtt(runtime: MqttRuntime) -> Result<(), String> {
    let addr: SocketAddr = runtime
        .config
        .bind_addr
        .parse()
        .map_err(|err| format!("invalid mqtt bind addr: {err}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| format!("bind mqtt listener failed: {err}"))?;
    serve_mqtt_listener(runtime, listener, addr, None).await
}

pub async fn serve_mqtt_tls(runtime: MqttRuntime, tls_acceptor: TlsAcceptor) -> Result<(), String> {
    let addr: SocketAddr = runtime
        .config
        .bind_addr
        .parse()
        .map_err(|err| format!("invalid mqtt bind addr: {err}"))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| format!("bind mqtt listener failed: {err}"))?;
    serve_mqtt_listener(runtime, listener, addr, Some(tls_acceptor)).await
}

pub(super) async fn serve_mqtt_listener(
    runtime: MqttRuntime,
    listener: TcpListener,
    addr: SocketAddr,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), String> {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::INFO,
        event = "mqtt.listener_started",
        listen_addr = %(addr.to_string()),
        tls_enabled = (tls_acceptor.is_some())
    );

    loop {
        let (socket, remote_addr) = listener
            .accept()
            .await
            .map_err(|err| format!("accept mqtt connection failed: {err}"))?;
        let socket = match tls_acceptor.as_ref() {
            Some(acceptor) => match acceptor.accept(socket).await {
                Ok(stream) => MqttStream::boxed(stream),
                Err(err) => {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::WARN,
                        event = "mqtt.tls_accept_failed",
                        remote_addr = %(remote_addr.to_string()),
                        error = %(err.to_string())
                    );
                    continue;
                }
            },
            None => MqttStream::boxed(socket),
        };
        let session = MqttSession::new(runtime.clone(), socket, remote_addr);
        tokio::spawn(
            async move { session.run().await }.instrument(tracing::info_span!(
                "gateway.mqtt.connection",
                remote_addr = %remote_addr
            )),
        );
    }
}
