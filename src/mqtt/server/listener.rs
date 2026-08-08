use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use super::MqttSession;
use crate::mqtt::MqttRuntime;

const MQTT_MAX_CONNECTIONS_PER_IP: usize = 64;

struct MqttIpPermit {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl MqttIpPermit {
    fn try_acquire(counts: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr) -> Option<Self> {
        let mut guard = counts.lock();
        let count = guard.entry(ip).or_default();
        if *count >= MQTT_MAX_CONNECTIONS_PER_IP {
            return None;
        }
        *count = count.saturating_add(1);
        Some(Self {
            counts: Arc::clone(counts),
            ip,
        })
    }
}

impl Drop for MqttIpPermit {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        let Some(count) = counts.get_mut(&self.ip) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&self.ip);
        }
    }
}

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

    let server_config = crate::private::warp_engine::default_server_config();
    let per_ip_counts = Arc::new(Mutex::new(HashMap::new()));
    let handshake_timeout = Duration::from_millis(server_config.hello_timeout_ms.max(1));
    let mut sessions = JoinSet::new();

    loop {
        let accepted = tokio::select! {
            biased;
            _ = runtime.private.wait_for_shutdown() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(join_error)) = joined {
                    ::tracing::event!(
                        target: "gateway.trace_event",
                        ::tracing::Level::ERROR,
                        event = "mqtt.connection_task_failed",
                        cancelled = (join_error.is_cancelled()),
                        panicked = (join_error.is_panic())
                    );
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (socket, remote_addr) =
            accepted.map_err(|err| format!("accept mqtt connection failed: {err}"))?;
        let session_permit = match runtime.private.try_acquire_session_admission() {
            Some(permit) => permit,
            None => {
                emit_admission_rejected(remote_addr, "global_session_limit");
                continue;
            }
        };
        let Some(ip_permit) = MqttIpPermit::try_acquire(&per_ip_counts, remote_addr.ip()) else {
            emit_admission_rejected(remote_addr, "per_ip_session_limit");
            continue;
        };
        let handshake_permit = match runtime.private.try_acquire_handshake_admission() {
            Some(permit) => permit,
            None => {
                emit_admission_rejected(remote_addr, "handshake_limit");
                continue;
            }
        };
        let acceptor = tls_acceptor.clone();
        let session_runtime = runtime.clone();
        let shutdown = Arc::clone(&runtime.private);
        let deadline = Instant::now() + handshake_timeout;
        sessions.spawn(
            async move {
                let _session_permit = session_permit;
                let _ip_permit = ip_permit;
                let socket = match acceptor {
                    Some(acceptor) => {
                        let accepted = tokio::select! {
                            _ = shutdown.wait_for_shutdown() => return,
                            accepted = timeout_at(deadline, acceptor.accept(socket)) => accepted,
                        };
                        match accepted {
                            Ok(Ok(stream)) => MqttStream::boxed(stream),
                            Ok(Err(err)) => {
                                ::tracing::event!(
                                    target: "gateway.trace_event",
                                    ::tracing::Level::WARN,
                                    event = "mqtt.tls_accept_failed",
                                    remote_addr = %(remote_addr.to_string()),
                                    error = %(err.to_string())
                                );
                                return;
                            }
                            Err(_) => {
                                emit_admission_rejected(remote_addr, "tls_handshake_timeout");
                                return;
                            }
                        }
                    }
                    None => MqttStream::boxed(socket),
                };
                MqttSession::new(
                    session_runtime,
                    socket,
                    remote_addr,
                    deadline,
                    handshake_permit,
                )
                .run()
                .await;
            }
            .instrument(tracing::info_span!(
                "gateway.mqtt.connection",
                remote_addr = %remote_addr
            )),
        );
    }

    while let Some(joined) = sessions.join_next().await {
        if let Err(join_error) = joined {
            ::tracing::event!(
                target: "gateway.trace_event",
                ::tracing::Level::ERROR,
                event = "mqtt.connection_task_failed",
                cancelled = (join_error.is_cancelled()),
                panicked = (join_error.is_panic())
            );
        }
    }
    Ok(())
}

fn emit_admission_rejected(remote_addr: SocketAddr, reason: &'static str) {
    ::tracing::event!(
        target: "gateway.trace_event",
        ::tracing::Level::WARN,
        event = "mqtt.connection_rejected",
        remote_addr = %(remote_addr.to_string()),
        reason = %(reason)
    );
}
