use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    sync::OwnedSemaphorePermit,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tracing::Instrument;
use warp_link::{
    ServerSessionIo, run_server_session,
    warp_link_core::{PeerMeta, ServerApp, ServerConfig, TransportKind, WarpLinkError},
    warp_link_transport::{FramedReader, write_prefixed_frame},
};

use crate::private::{
    PrivateState,
    tls::ServerTlsIdentity,
    warp_engine::{PushgoServerApp, default_server_config},
};

pub async fn serve_quic(
    bind_addr: &str,
    cert_path: &str,
    key_path: &str,
    state: Arc<PrivateState>,
) -> Result<(), String> {
    let address: SocketAddr = bind_addr
        .parse()
        .map_err(|error| format!("invalid quic listen addr: {error}"))?;
    let mut config = default_server_config();
    config.quic_listen_addr = Some(bind_addr.to_owned());
    config.quic_alpn = "pushgo-quic".to_owned();
    let tls = ServerTlsIdentity::load(cert_path, key_path)?.into_quic_config(&config.quic_alpn)?;
    let endpoint = quinn::Endpoint::server(tls, address)
        .map_err(|error| format!("bind quic listener failed: {error}"))?;
    let app: Arc<dyn ServerApp> = Arc::new(PushgoServerApp::new(state.clone()));
    let mut sessions = JoinSet::new();
    loop {
        let incoming = tokio::select! {
            biased;
            _ = state.wait_for_shutdown() => break,
            joined = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = joined {
                    fence_session_failure(&state, &error.to_string());
                }
                continue;
            }
            incoming = endpoint.accept() => incoming,
        };
        let Some(incoming) = incoming else { break };
        let Some(session_permit) = state.try_acquire_session_admission() else {
            incoming.refuse();
            continue;
        };
        let Some(handshake_permit) = state.try_acquire_handshake_admission() else {
            incoming.refuse();
            continue;
        };
        let session_state = state.clone();
        let session_app = app.clone();
        let session_config = config.clone();
        let remote = incoming.remote_address();
        sessions.spawn(
            async move {
                serve_connection(
                    incoming,
                    session_state,
                    session_app,
                    session_config,
                    session_permit,
                    handshake_permit,
                )
                .await;
            }
            .instrument(
                tracing::info_span!("gateway.private.quic.connection", remote_addr = %remote),
            ),
        );
    }
    // Closing transport I/O wakes the engine; its owning future is still joined
    // through on_disconnect and any durable ACK/release already in progress.
    endpoint.close(quinn::VarInt::from_u32(0), b"gateway shutdown");
    while let Some(joined) = sessions.join_next().await {
        if let Err(error) = joined {
            fence_session_failure(&state, &error.to_string());
        }
    }
    endpoint.wait_idle().await;
    Ok(())
}

fn fence_session_failure(state: &PrivateState, error: &str) {
    state.record_session_task_failure("Private QUIC session task failed");
    tracing::error!(error, "Private QUIC session task failed");
}

async fn serve_connection(
    incoming: quinn::Incoming,
    state: Arc<PrivateState>,
    app: Arc<dyn ServerApp>,
    config: ServerConfig,
    _session_permit: OwnedSemaphorePermit,
    handshake_permit: OwnedSemaphorePermit,
) {
    let remote = incoming.remote_address().to_string();
    let mut deadline = Instant::now() + Duration::from_millis(config.hello_timeout_ms.max(1));
    let connected = tokio::select! {
        _ = state.wait_for_shutdown() => return,
        connected = timeout_at(deadline, incoming) => connected,
    };
    let connection = match connected {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            report_handshake_error(&app, &remote, WarpLinkError::Transport(error.to_string()))
                .await;
            return;
        }
        Err(_) => {
            report_handshake_error(
                &app,
                &remote,
                WarpLinkError::Timeout("quic handshake timeout".to_owned()),
            )
            .await;
            return;
        }
    };
    let mut handshake_permit = Some(handshake_permit);
    loop {
        if state.is_shutting_down() {
            break;
        }
        let streams = tokio::select! {
            _ = state.wait_for_shutdown() => break,
            streams = timeout_at(deadline, connection.accept_bi()) => streams,
        };
        let (send, recv) = match streams {
            Ok(Ok(streams)) => streams,
            Ok(Err(_)) => break,
            Err(_) => {
                report_handshake_error(
                    &app,
                    &remote,
                    WarpLinkError::Timeout("quic accept stream timeout".to_owned()),
                )
                .await;
                break;
            }
        };
        if handshake_permit.is_none() {
            handshake_permit = state.try_acquire_handshake_admission();
            if handshake_permit.is_none() {
                break;
            }
        }
        let mut io = QuicSessionIo {
            send,
            recv: FramedReader::new(recv),
            prefetched: None,
            write_timeout_ms: config.write_timeout_ms,
        };
        let hello = tokio::select! {
            _ = state.wait_for_shutdown() => break,
            hello = timeout_at(deadline, io.recv.read_frame()) => hello,
        };
        match hello {
            Ok(Ok(frame)) => io.prefetched = Some(frame),
            Ok(Err(error)) => {
                report_handshake_error(&app, &remote, error).await;
                break;
            }
            Err(_) => {
                report_handshake_error(
                    &app,
                    &remote,
                    WarpLinkError::Timeout("quic hello deadline exceeded".to_owned()),
                )
                .await;
                break;
            }
        }
        drop(handshake_permit.take());
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
        else {
            break;
        };
        let mut session_config = config.clone();
        session_config.hello_timeout_ms = remaining.as_millis().clamp(1, u64::MAX as u128) as u64;
        let peer = PeerMeta {
            transport: TransportKind::Quic,
            remote_addr: Some(remote.clone()),
        };
        if let Err(error) = run_server_session(&session_config, app.clone(), &mut io, peer).await {
            tracing::debug!(error = %error, "Private QUIC session ended");
        }
        deadline = Instant::now() + Duration::from_millis(config.hello_timeout_ms.max(1));
    }
    connection.close(quinn::VarInt::from_u32(0), b"session ended");
}

async fn report_handshake_error(app: &Arc<dyn ServerApp>, remote: &str, error: WarpLinkError) {
    app.on_handshake_failure(
        PeerMeta {
            transport: TransportKind::Quic,
            remote_addr: Some(remote.to_owned()),
        },
        &error,
    )
    .await;
}

struct QuicSessionIo {
    send: quinn::SendStream,
    recv: FramedReader<quinn::RecvStream>,
    prefetched: Option<Vec<u8>>,
    write_timeout_ms: u64,
}

#[async_trait]
impl ServerSessionIo for QuicSessionIo {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_timeout_ms.max(1)),
            write_prefixed_frame(&mut self.send, frame),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("quic write timeout".to_owned()))??;
        Ok(())
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        if let Some(frame) = self.prefetched.take() {
            return Ok(frame);
        }
        timeout(
            Duration::from_millis(timeout_ms.max(1)),
            self.recv.read_frame(),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("quic read timeout".to_owned()))?
    }
}
